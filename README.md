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

## Documentation

- [Integrate r2connect](docs/integration.md): sign-in, bucket selection, using
  and renewing credentials, disconnecting, errors, platforms and testing.
- [Configure the Cloudflare OAuth client](docs/cloudflare-oauth-client.md):
  the one-time registration in your Cloudflare account, through the dashboard
  or the API.
- [API reference](https://pkg.go.dev/github.com/knothhe/r2connect)

## Quick start

1. Register an OAuth client. Or hand this prompt to a coding agent that can run
   commands or use your browser:

   > Follow https://github.com/knothhe/r2connect/blob/main/docs/cloudflare-oauth-client.md to register a private Cloudflare OAuth client named `<app name>` with redirect URL `<http://localhost:port/path>`, then tell me its Client ID.

2. Install the module:

   ```sh
   go get github.com/knothhe/r2connect@latest
   ```

3. Wire it up:

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

Tell users before they authorize: on Cloudflare's consent page, click **Edit
Permissions** and turn on **Account API Tokens Write**. Cloudflare leaves it
unticked by default, and sign-in fails without it.

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
