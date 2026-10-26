# r2connect

Connect a desktop application to a user's own Cloudflare R2 bucket through
OAuth, without a client secret and without asking the user to paste API keys.

r2connect signs the user in with PKCE on a loopback callback, lists their
accounts and buckets, and provisions S3 credentials restricted to the one
bucket they chose. The credentials expire, are renewed silently before they
do, and are removed again on disconnect. Object data then uses any S3 client.

```
r2connect            Client (Cloudflare control plane) and Manager (credential lifecycle)
r2connect/loopback   native authorization-code flow on a local callback listener
r2connect/keyring    SecretStore on the macOS Keychain, Windows Credential Manager
                     or a Linux Secret Service keyring
```

## Usage

Register a Cloudflare OAuth client that allows the Refresh Token grant, the
scopes in `r2connect.OAuthScopes`, and a loopback redirect URI such as
`http://localhost:18796/oauth/cloudflare/callback`.

```go
client := r2connect.NewClient(clientID)
manager := r2connect.NewManager(client, r2connect.ManagerOptions{
	Secrets:         keyring.New("com.example.app.r2", "Example credentials"),
	State:           r2connect.FileStateStore{Path: filepath.Join(dataDir, "r2-oauth-state.json")},
	TokenNamePrefix: "example-",
})

// Sign in: the grant is saved before the browser page reports success.
_, err := loopback.Authorize(ctx, client, loopback.Options{
	RedirectURI: "http://localhost:18796/oauth/cloudflare/callback",
	Accept:      manager.Authorize,
}, openBrowser)

// Choose a bucket and provision credentials for it.
accounts, err := manager.Accounts(ctx)
buckets, err := manager.Buckets(ctx, accounts[0].ID, "default")
conn, err := manager.Connect(ctx, accounts[0].ID, buckets[0].Name, "default")

// Before each use: renewed automatically near expiry.
creds, err := manager.Credentials(ctx, conn)
endpoint, err := r2connect.Endpoint(conn.AccountID, conn.Jurisdiction)
// S3 client: endpoint, region "auto", path-style, creds.AccessKeyID / creds.SecretAccessKey.

// Remove every token, revoke the grant and forget it.
err = manager.Disconnect(ctx)
```

Persist `conn.ID`, `AccountID`, `Bucket` and `Jurisdiction` with your own
configuration; `Credentials` only returns credentials for an exact match.

For a sign-in the user can cancel, use `loopback.Start`, open `Flow.URL()`, and
call `Flow.Wait` with a cancelable context. `Options.Done` receives the result
before the browser page is written, so status shown in the application is
already current when the user returns.

## Failure handling

- Every external change is compensated: a token whose credentials could not be
  saved is deleted again, and a deletion that fails is remembered for
  `Disconnect` to retry. `ManagerOptions.OnWarning` reports such cleanup.
- A rotating refresh token survives a failed secret write, so it is never
  reused after Cloudflare has invalidated it.
- A failed early renewal keeps returning the still-valid credentials and backs
  off; only credentials about to expire make `Credentials` fail.
- `keyring.Store` stops touching the credential store after the user refuses
  its prompt, until `RetryAccess` is called for an explicit user action.
- Unreadable saved state is reported by `LoadError` and never overwritten.

## Testing

```
go test -race ./...
```

`R2CONNECT_TEST_SECRET_SERVICE=1` also runs a round trip against the real
Linux session keyring.
