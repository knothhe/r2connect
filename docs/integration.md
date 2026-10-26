# Integrate r2connect

This guide walks a desktop application from "connect Cloudflare" to syncing
objects with credentials that renew themselves. It assumes you have registered
an OAuth client as described in
[Configure the Cloudflare OAuth client](cloudflare-oauth-client.md).

```sh
go get github.com/knothhe/r2connect@latest
```

## How the pieces fit

```
your UI ── loopback.Flow ──▶ browser ──▶ Cloudflare consent ──▶ http://localhost:<port>/<path>
                │                                                        │
                │  code + PKCE verifier ──▶ Client.ExchangeCode ◀────────┘
                ▼
         Manager.Authorize ──▶ SecretStore (OAuth grant)
                │                StateStore  (non-secret metadata)
                ▼
  Manager.Accounts / Buckets / Connect ──▶ bucket-scoped API token ──▶ S3 credentials
                ▼
       Manager.Credentials (renews near expiry) ──▶ your S3 client
```

| Type | Role |
| --- | --- |
| `r2connect.Client` | Stateless calls to Cloudflare's OAuth and API endpoints. |
| `r2connect.Manager` | Owns one grant and its connections; all lifecycle rules live here. |
| `loopback.Flow` | One sign-in: PKCE, the local callback listener, the code exchange. |
| `keyring.Store` | Secrets in the macOS Keychain, Windows Credential Manager or Secret Service. |
| `r2connect.FileStateStore` | Metadata as a JSON file, replaced atomically. Holds no secrets. |

## 1. Create the Manager once

Create one `Client` and one `Manager` per user library and keep them for the
life of the process. A `Manager` is safe for concurrent use.

```go
client := r2connect.NewClient(clientID) // the public Client ID from registration

secrets := keyring.New(
	"com.example.app.r2",  // service: namespaces your items in the credential store
	"Example credentials", // label: what the store's UI shows for each item
)

manager := r2connect.NewManager(client, r2connect.ManagerOptions{
	Secrets:         secrets,
	State:           r2connect.FileStateStore{Path: filepath.Join(dataDir, "r2-oauth-state.json")},
	TokenNamePrefix: "example-", // API tokens show up as example-<id> in the dashboard
	OnWarning:       func(w r2connect.Warning) { /* see "Warnings" */ },
})
if err := manager.LoadError(); err != nil {
	// errors.Is(err, r2connect.ErrInvalidOptions): fix the ManagerOptions.
	// errors.Is(err, r2connect.ErrInvalidState): the state file exists but
	// cannot be used. It is left untouched; offer manual configuration and do
	// not delete it automatically.
}
```

- If the user can keep several independent libraries (or you ship development
  and release builds side by side), give each its own `service` and state
  path. Hashing the data directory into the service name keeps paths out of
  the keychain.
- The defaults are 30-day credentials, silent renewal within 7 days of expiry,
  a 5-minute hard margin and a 1-hour back-off after a failed early renewal.
  Override them in `ManagerOptions` only if you have a reason to.
  `NewManager` rejects inconsistent values with `ErrInvalidOptions`:
  `CredentialLifetime` must be longer than `RenewalWindow` and exceed
  `ExpiryMargin` by more than a minute, or fresh credentials would be renewed
  on every use. Shortening the lifetime therefore means shortening the window
  too. `TokenNamePrefix` is limited to 108 bytes.
- Each Cloudflare request times out after 30 seconds; set
  `client.RequestTimeout` to change it.
- `OnWarning` runs while the Manager is locked. Do not call the Manager from
  it, and do not hold a lock of yours that a Manager call might also need.

## 2. Sign in

Run a cancelable flow so your UI can show "waiting for the browser" with a
Cancel button.

```go
const redirectURI = "http://localhost:18796/oauth/cloudflare/callback" // must match the registration

func (a *App) StartSignIn() error {
	if err := a.manager.CheckClient(); err != nil {
		return err // ErrClientChanged: connections made with another Client ID remain
	}
	flow, err := loopback.Start(a.client, loopback.Options{
		RedirectURI: redirectURI,
		Accept:      a.manager.Authorize,  // saves the grant before the browser hears "success"
		Done:        a.showSignInResult,   // called once, before the browser page is written
		Messages:    loopback.Messages{Connected: "Connected. Return to Example."},
	})
	if err != nil {
		return err // loopback.ErrListen: the port is busy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancelSignIn = cancel
	go func() {
		defer cancel()
		flow.Wait(ctx)
	}()
	return openBrowser(flow.URL())
}

func (a *App) CancelSignIn() { a.cancelSignIn() }
```

`Done` receives one of:

| Result | Show the user |
| --- | --- |
| `nil` | Connected; continue to bucket selection. |
| `errors.Is(err, loopback.ErrDenied)` | Denied or canceled. Tell them to click **Edit Permissions** and turn on **Account API Tokens Write**. |
| `errors.Is(err, loopback.ErrInvalidScope)` | Your OAuth client registration is wrong; see the client setup guide. |
| other `*loopback.OAuthError` | Not authorized; offer a retry. |
| `context.DeadlineExceeded` / `context.Canceled` | Timed out / canceled. |
| `loopback.ErrCallbackStopped` | The listener stopped unexpectedly; retry. |
| `r2connect.ErrMissingScopes`, `ErrAccountsMissing` | Retry and grant everything requested, including every previously connected account. |

The first sign-in hint matters most: Cloudflare's consent page leaves
Account API Tokens Write unticked by default. Show that instruction before the
browser opens, not only after a failure.

For a tool without a UI, `loopback.Authorize(ctx, client, opts, openBrowser)`
does all of this in one blocking call.

Calling `keyring.Store.RetryAccess` here is a good idea if the user earlier
refused a keychain prompt: a refusal stops all access until an explicit user
action such as Connect.

## 3. Choose a bucket

```go
accounts, err := manager.Accounts(ctx)
buckets, err := manager.Buckets(ctx, accountID, jurisdiction) // "" or "default", "eu", "fedramp", "us"
conn, err := manager.Connect(ctx, accountID, bucketName, jurisdiction)
```

`Connect` re-checks the bucket with Cloudflare, then creates an API token that
can only read and write objects in that bucket. Every call creates a new
connection, so call it when the user confirms a choice, not on every
selection change.

Save the selection with your own configuration:

```go
type R2Profile struct {
	ConnectionID string // conn.ID
	AccountID    string
	Bucket       string
	Jurisdiction string
}
```

If the user abandons a selection (closes the dialog, picks another bucket),
release it so its token does not linger until expiry:

```go
err := manager.Discard(ctx, conn.ID) // idempotent
```

When a saved profile is replaced, discard the previous connection *after* the
new profile is saved.

## 4. Use the credentials

Ask the Manager before each sync session. It returns the saved credentials, or
renews them first when they are close to expiry.

```go
creds, err := manager.Credentials(ctx, r2connect.Connection{
	ID: p.ConnectionID, AccountID: p.AccountID, Bucket: p.Bucket, Jurisdiction: p.Jurisdiction,
})
endpoint, err := r2connect.Endpoint(p.AccountID, p.Jurisdiction)
```

Configure any S3 client with:

| S3 setting | Value |
| --- | --- |
| Endpoint | `endpoint` |
| Region | `auto` |
| Addressing | path-style |
| Access key ID | `creds.AccessKeyID` |
| Secret access key | `creds.SecretAccessKey` |
| Session token | none |

For example, with the AWS SDK for Go v2:

```go
s3Client := s3.New(s3.Options{
	BaseEndpoint: aws.String(endpoint),
	Region:       "auto",
	UsePathStyle: true,
	Credentials:  credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, ""),
})
```

Do not store `creds` in your configuration; the Manager already keeps them in
the SecretStore and replaces them on renewal. `Credentials` returns
`ErrUnknownConnection` unless all four fields match a saved connection, so a
tampered configuration never receives credentials.

Renewal rules, so you know what to expect:

- With a refresh token, credentials renew silently once they expire within the
  renewal window. If that fails, the current credentials are still returned
  and the Manager retries after the back-off.
- Without a refresh token (or after it stops working), credentials renew only
  just before they expire, and only while the access token is still valid.
  Otherwise `Credentials` fails with `ErrAuthorizationExpired`: ask the user to
  connect again. Valid S3 credentials keep working meanwhile.

## 5. Disconnect

```go
err := manager.Disconnect(ctx)
```

This deletes every connection's API token and saved credentials, removes
leftover tokens from earlier failures, revokes the OAuth grant and forgets it.
If it fails, keep showing the user as connected and let them retry: remote
deletions are idempotent, and a grant already revoked is not used again.
`ErrCleanupPending` means the grant is revoked but some tokens remain; a new
sign-in lets `Disconnect` finish. Clear your saved profile after it succeeds.

When `Disconnect` cannot finish at all, for example because the user revoked
the grant in the Cloudflare dashboard and no longer has access to a connected
account, offer `Forget` as an explicit "remove from this device" action:

```go
leftover, err := manager.Forget()
```

It deletes every saved secret and clears the state without contacting
Cloudflare. `leftover` lists the API tokens (account and token ID) that may
still exist; tell the user to delete them in the dashboard. The OAuth grant is
not revoked either.

## Errors and warnings

Manager errors are sentinels with user-ready English messages, so you can show
`err.Error()` directly or match them with `errors.Is` to show your own text:

| Error | Meaning |
| --- | --- |
| `ErrNotAuthorized` | No saved grant for this client. |
| `ErrAuthorizationInvalid` | The saved grant is unreadable; connect again. |
| `ErrAuthorizationExpired` | Code-only grant expired; connect again. |
| `ErrMissingScopes` | The grant lacks a required scope. |
| `ErrAccountsMissing` | A new grant omits an account that still has connections. |
| `ErrClientChanged` | Connections from another Client ID remain; restore it to disconnect them, or `Forget`. |
| `ErrBucketUnavailable` | The bucket is not in that account and jurisdiction. |
| `ErrTooManyConnections` | More than `MaxConnections` pending; disconnect to clean up. |
| `ErrUnknownConnection` | No saved connection matches. |
| `ErrCredentialsInvalid` | Saved credentials are unreadable; reconnect the bucket. |
| `ErrCleanupPending` | See Disconnect. |
| `ErrInvalidOptions` | `ManagerOptions` are inconsistent; a programming error. |
| `ErrInvalidState` | The saved state file cannot be used; it is left untouched. |
| `*r2connect.APIError` | A Cloudflare API failure; its message is sanitized. |

Warnings report cleanup that failed after the operation itself succeeded. The
Manager remembers what is left and `Disconnect` retries it, so a warning is
informational: show it, for example, as "Disconnect to retry cleanup".

| Warning | When |
| --- | --- |
| `WarningUnusedToken` | A token created by a failed operation could not be deleted. |
| `WarningRetiredToken` | Credentials were renewed but the old token could not be deleted. |
| `WarningAuthorizationCleanup` | A new grant was saved but the old one could not be removed locally. |

`keyring` errors: `ErrAccessDenied` (the user refused the prompt; access stops
until `RetryAccess`), `ErrStoreMissing` and `ErrUnavailable` (no usable store
on this machine). `keyring.Unusable(err)` tells these apart from transient
failures, for example to fall back to asking for credentials each time.

## Diagnostics

Both hooks carry only allowlisted fields: no URLs, codes, tokens, account IDs
or bucket names. They are safe to write to a local log.

```go
client.Diagnostic = func(e r2connect.DiagnosticEvent) { log.Printf("cloudflare %+v", e) }
opts.Diagnostic = func(e loopback.Event) { log.Printf("sign-in %s %s", e.Stage, e.Result) }
```

When a sign-in fails, the loopback stages tell you how far it got: no
`callback_received` means the browser never reached your listener (wrong
redirect URL, or a Cloudflare-side error such as the hidden-scope 1420);
`code_exchange_finished` with `failed` means the code was rejected.

## Platforms

| Platform | Credential store | Notes |
| --- | --- | --- |
| macOS | Keychain | Requires cgo. Sign your app with a stable identity, or the Keychain asks again after each update. |
| Windows | Credential Manager | Values longer than one item are split across several items automatically. |
| Linux | Secret Service (GNOME Keyring, KWallet, KeePassXC) | Needs a running, unlockable keyring on the session bus; otherwise `ErrStoreMissing`. |
| Other | none | `keyring.ErrUnavailable`; supply your own `SecretStore`. |

`SecretStore` and `StateStore` are small interfaces; implement them to keep
secrets or metadata elsewhere.

## Testing your integration

- Point a `Client` at a fake server: set `APIBaseURL` and `OAuthBaseURL`.
  Overrides may use plain HTTP only on a loopback address.
- Use `keyring.NewWithBackend` with an in-memory `keyring.Backend`, so tests
  never touch the real keychain.
- Use `FileStateStore` in `t.TempDir()`, or wrap it to inject save failures.

r2connect's own [manager_test.go](../manager_test.go) and
[loopback_test.go](../loopback/loopback_test.go) contain a complete fake of the
Cloudflare endpoints you can copy.

## Security model

- No client secret; PKCE S256 with a fresh verifier per sign-in.
- The callback listens only on loopback, only while signing in, accepts one
  code per sign-in and compares `state` in constant time.
- Bucket tokens have one permission (bucket item write) on one bucket and
  expire. Replaced tokens are deleted.
- OAuth tokens and S3 secrets live only in the SecretStore. The state file
  holds the Client ID, connection IDs, account, bucket, token IDs and expiry
  times.
