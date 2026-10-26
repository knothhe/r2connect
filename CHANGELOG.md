# Changelog

All notable changes to this module are recorded here. Versions follow
[Semantic Versioning](https://semver.org/).

## v0.1.1 - 2026-10-26

### Added

- `Manager.Forget` clears the saved authorization, connections and pending
  cleanup from this device without contacting Cloudflare, and returns the API
  tokens that may remain. It is the way out when `Disconnect` cannot finish.
- `ErrInvalidOptions`: `NewManager` rejects inconsistent `ManagerOptions`
  (missing stores, negative values, a `CredentialLifetime` not longer than
  `RenewalWindow` or `ExpiryMargin` plus a minute, a `TokenNamePrefix` over 108
  bytes). Previously a short lifetime renewed credentials on every use.
- `Client.RequestTimeout` sets the per-request timeout (default 30 seconds).
- MIT license.
- CI on Linux, macOS and Windows with vet, race tests, staticcheck and
  govulncheck.

### Changed

- Every saved-state validation failure now matches `ErrInvalidState` with
  `errors.Is`.
- `Disconnect` and `Discard` report `ErrClientChanged` when connections were
  made with another OAuth client, and `Disconnect` forgets such a grant locally
  when nothing remains to clean up.
- A failed early renewal backs off only for that connection.
- `FileStateStore` syncs the directory after replacing the file.
- The minimum Go version is now 1.25.

### Fixed

- The macOS keyring backend rejects an empty value instead of panicking.

## v0.1.0 - 2026-10-26

- Initial release: the Cloudflare control-plane `Client` and the `Manager`
  credential lifecycle, the `loopback` authorization-code flow and the
  `keyring` SecretStore for macOS, Windows and Linux.
