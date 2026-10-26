# Configure the Cloudflare OAuth client

r2connect signs users in through an OAuth client that you, the application's
publisher, register once in your own Cloudflare account. Your users never
create a client, see a Client ID or paste an API token. This page covers that
one-time registration.

Shortcut: give an agent the one-line prompt in
[Let an agent configure it](#let-an-agent-configure-it).

## What to register

| Setting | Value |
| --- | --- |
| Client name | Your application's name, shown on the consent page |
| Grant types | Authorization Code (`authorization_code`) **and** Refresh Token (`refresh_token`) |
| Response type | Code (`code`) |
| Token endpoint authentication | None (`none`): a public client using PKCE, with no client secret |
| Redirect URL | `http://localhost:<port>/<path>`, exactly as your application passes it to `loopback.Options.RedirectURI` |
| Client URL | Optional while private; required before the client is made public |

Scopes, all four **Required**:

| Dashboard permission | Scope ID | Used for |
| --- | --- | --- |
| Account Settings Read | `account-settings.read` | List the accounts the user can reach |
| Workers R2 Storage Read | `workers-r2.read` | List buckets |
| Workers R2 Storage Bucket Item Write | `workers-r2-bucket-item.write` | Object read and write in the chosen bucket |
| Account API Tokens Write | `account-api-tokens.write` | Create and delete the bucket-scoped tokens |

These are `r2connect.RequiredScopes()`. r2connect also requests
`offline_access`, which is not registered as a scope; it asks for a refresh
token so credentials renew without a browser.

### Rules that cause most failures

- **Tick the Refresh Token grant.** Without it, Cloudflare may reject sign-in
  with `invalid_scope` (`loopback.ErrInvalidScope`). If a grant arrives
  without a refresh token, r2connect still works, but every renewal after the
  access token expires needs a new sign-in.
- **Choose Workers R2 Storage Read**, not Workers R2 Storage *Bucket Item*
  Read. The bucket list API accepts only Storage Read or Write.
- **Use the dotted scope IDs** from `GET /client/v4/oauth/scopes`, such as
  `account-api-tokens.write`. Older colon names such as
  `account_api_tokens:create` are not these scopes.
- **The redirect URL must match character for character**, port and path
  included. `localhost` and `127.0.0.1` are different registrations. Do not
  assume wildcard ports or custom URL schemes work. Pick a fixed port no other
  application on the user's machine is likely to use; r2connect reports a busy
  port as `loopback.ErrListen`.
- **Never create or embed a client secret.** A desktop application cannot keep
  one secret; PKCE replaces it.

### The consent page hides one scope

Even with all four scopes Required, Cloudflare's consent page lists Account
API Tokens Write under *Additional access → Sensitive scopes*, unticked. A user
who clicks Authorize straight away submits three scopes; Cloudflare answers
with HTTP 400 (code 1420, "Required scopes cannot be omitted from the grant")
on its own page and never calls your redirect URL. Tell users, before they
connect and while you wait, to click **Edit Permissions** and turn on
**Account API Tokens Write** before authorizing. Cloudflare also reports Cancel
this way, as `access_denied` (`loopback.ErrDenied`); show the same hint then.

### Who can authorize

The signing-in user needs the API Token Provisioning or Super Administrator
role on the account. The bucket tokens r2connect creates can never exceed the
intersection of that user's permissions and the granted scopes. r2connect only
uses existing buckets; it does not enable R2 or create buckets.

## Option A: the dashboard

1. Sign in at <https://dash.cloudflare.com> and select the account that will
   own the client. You need Super Administrator, Administrator or OAuth Client
   Write.
2. Go to **Manage Account → OAuth clients → Create client**.
3. Fill in the fields from [What to register](#what-to-register) and click
   **Continue**.
4. Select the four scopes and leave each one **Required**.
5. Create the client and copy its **Client ID**. If a secret is offered, do not
   create or copy one.

## Option B: the API

Create an API token with the **OAuth Clients Write** permission for the
account, then:

```sh
export CLOUDFLARE_ACCOUNT_ID=...   # the account that will own the client
export CLOUDFLARE_API_TOKEN=...    # OAuth Clients Write

# Confirm the scope IDs first.
curl -s https://api.cloudflare.com/client/v4/oauth/scopes \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"

curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/oauth_clients" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "client_name": "Example",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "redirect_uris": ["http://localhost:18796/oauth/cloudflare/callback"],
    "scopes": ["account-settings.read", "workers-r2.read", "workers-r2-bucket-item.write", "account-api-tokens.write"]
  }'
```

Read the Client ID from the response's `result`. Leave `optional_scopes`
out so every scope stays required. Delete the API token afterwards if you made
it only for this.

## Private and public clients

A new client is **private**: only members of the account that owns it can
authorize it. That is the right state for development and testing.

To let any Cloudflare user connect, the client needs a name, logo, client URL
and scopes, and the client URL's domain must be verified with a DNS TXT
record. Then choose **Change Visibility** in the dashboard, or
`PATCH /accounts/{account_id}/oauth_clients/{client_id}` with
`{"visibility": "public"}`. **Making a client public is permanent.**

## Put the Client ID in your application

The Client ID is public; embed it in the build:

```go
client := r2connect.NewClient("your-public-client-id")
```

Keep the redirect URL in one place that both the registration and
`loopback.Options.RedirectURI` come from. If you change either, change both.

## Check the registration

With the Client ID in a development build:

1. Start sign-in. The browser should show your client name and all four
   permissions; turn on Account API Tokens Write and authorize.
2. The redirect should reach your loopback listener, and `Manager.Authorize`
   should accept the grant. `ErrMissingScopes` means a scope was not granted.
3. `Manager.Accounts` and `Manager.Buckets` should list the test account's
   buckets.
4. `Manager.Connect` should create an account API token (**Manage Account →
   Account API Tokens**) named with your `TokenNamePrefix`, restricted to that
   one bucket and valid 30 days.
5. `Manager.Disconnect` should remove that token and revoke the grant.

| Symptom | Likely cause |
| --- | --- |
| `invalid_scope` on the callback | Refresh Token grant not ticked, or a scope ID the client is not registered for |
| Cloudflare page shows code 1420 | Account API Tokens Write left unticked on the consent page |
| The browser never returns to the app | Redirect URL differs from the registration, or the app stopped listening (canceled or timed out) |
| `ErrMissingScopes` | The grant lacks a required scope |
| Creating credentials fails with HTTP 403 | The user lacks API Token Provisioning, or R2 is not enabled on the account |
| Only account members can sign in | The client is still private |

## Let an agent configure it

Give a coding agent that can run commands, or drive your browser, this prompt,
replacing the parts in angle brackets:

> Follow https://github.com/knothhe/r2connect/blob/main/docs/cloudflare-oauth-client.md to register a private Cloudflare OAuth client named `<app name>` with redirect URL `<http://localhost:port/path>`, then tell me its Client ID.

中文：

> 按 https://github.com/knothhe/r2connect/blob/main/docs/cloudflare-oauth-client.md 为 `<应用名>` 注册一个 private 的 Cloudflare OAuth client，回调地址用 `<http://localhost:端口/路径>`，完成后告诉我它的 Client ID。

### Instructions for agents

If you are an agent asked to do this:

1. Read this whole page first. The values in
   [What to register](#what-to-register) are not negotiable; ask the user only
   for the application name, the redirect URL and which account to use.
2. Use the API (Option B) when `CLOUDFLARE_API_TOKEN` and
   `CLOUDFLARE_ACCOUNT_ID` are already set in the environment. Do not ask the
   user to paste a token into the chat, and never print it. Otherwise use the
   dashboard (Option A) in the user's signed-in browser; if the user is not
   signed in, stop and ask them to sign in.
3. Before creating, check **Manage Account → OAuth clients** for a client with
   the same name or redirect URL; if one exists, ask before making a second.
4. Create the client **private**. Do not change visibility, create a client
   secret, make any scope optional, or change other clients.
5. Confirm the created client has both grant types, auth method `none`, the
   exact redirect URL and all four scopes. Report any difference instead of
   working around it.
6. Reply with the Client ID, the account it belongs to, and the checks from
   [Check the registration](#check-the-registration) that the user still has to
   do by signing in.

## References

- [Create an OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
- [Account API token provisioning through OAuth](https://developers.cloudflare.com/changelog/post/2026-10-01-account-api-token-provisioning/)
- [R2 bucket-scoped tokens and S3 credentials](https://developers.cloudflare.com/r2/api/tokens/)
- [List R2 buckets](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list/)
