package r2connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Errors returned by Manager. Their messages are written for end users.
var (
	ErrNotAuthorized        = errors.New("Connect Cloudflare before choosing a bucket.")
	ErrAuthorizationInvalid = errors.New("Saved Cloudflare authorization is invalid. Reconnect Cloudflare.")
	ErrAuthorizationExpired = errors.New("Cloudflare authorization expired. Connect Cloudflare again to manage R2 credentials.")
	ErrMissingScopes        = errors.New("Cloudflare authorization is missing required permissions. Reconnect and grant the requested permissions.")
	ErrAccountsMissing      = errors.New("Include every previously connected Cloudflare account when reconnecting, or disconnect its R2 buckets first.")
	ErrClientChanged        = errors.New("The OAuth client ID changed. Restore the original client ID and disconnect its R2 buckets before using a different OAuth client.")
	ErrBucketUnavailable    = errors.New("Choose a bucket available in this Cloudflare account and jurisdiction.")
	ErrTooManyConnections   = errors.New("Too many pending Cloudflare connections. Disconnect Cloudflare to clean up before reconnecting.")
	ErrUnknownConnection    = errors.New("Choose a Cloudflare bucket before saving or syncing.")
	ErrCredentialsInvalid   = errors.New("Saved R2 credentials are invalid. Reconnect the bucket.")
	// ErrCleanupPending reports that Disconnect revoked the authorization but
	// some API tokens remain; authorizing again lets Disconnect remove them.
	ErrCleanupPending = errors.New("Reconnect Cloudflare to remove the remaining R2 tokens.")
)

// Warning reports cleanup that failed after the operation itself succeeded.
// The Manager remembers what is left, and Disconnect retries it.
type Warning int

const (
	// WarningUnusedToken: an API token created by a failed operation could not
	// be removed.
	WarningUnusedToken Warning = iota + 1
	// WarningRetiredToken: credentials were renewed, but the replaced API token
	// could not be removed.
	WarningRetiredToken
	// WarningAuthorizationCleanup: a new authorization was saved, but an older
	// one could not be removed from the SecretStore.
	WarningAuthorizationCleanup
)

// SecretStore keeps the OAuth grant and bucket credentials. Delete of a
// missing key must succeed. *keyring.Store implements it.
type SecretStore interface {
	Load(key string) ([]byte, error)
	Save(key string, value []byte) error
	Delete(key string) error
}

type ManagerOptions struct {
	Secrets SecretStore
	State   StateStore
	// TokenNamePrefix starts the name of each API token in the Cloudflare
	// dashboard. Default "r2connect-".
	TokenNamePrefix string
	// CredentialLifetime is how long each API token lasts. Default 30 days.
	CredentialLifetime time.Duration
	// RenewalWindow: with a refresh token, credentials are renewed silently once
	// they expire within this window. Default 7 days.
	RenewalWindow time.Duration
	// ExpiryMargin: credentials expiring within this margin are always renewed,
	// even without a refresh token. Default 5 minutes.
	ExpiryMargin time.Duration
	// RenewalRetryDelay spaces out failed early renewals. Default 1 hour.
	RenewalRetryDelay time.Duration
	// MaxConnections bounds pending and saved connections. Default 16.
	MaxConnections int
	// OnWarning runs while the Manager is locked; it must not call the Manager.
	OnWarning func(Warning)
}

// Status summarizes the saved authorization without reading secrets.
type Status struct {
	Authorized bool
	Renewable  bool
}

// Manager owns one OAuth grant and the bucket connections provisioned with it.
// It is safe for concurrent use.
type Manager struct {
	mu      sync.Mutex
	client  *Client
	opts    ManagerOptions
	state   State
	loadErr error
	// A rotating refresh token must survive a transient SecretStore write
	// failure without reusing its now-invalid predecessor on the next attempt.
	pendingTokens *TokenSet
	// Metadata writes can fail after an external mutation. Keep compensation
	// records in memory until a subsequent successful write can persist them.
	pendingRetired []RetiredToken
	// Disconnect revoked the grant but could not finish locally.
	revoked bool
	// Failed early renewals wait before retrying while credentials stay valid.
	renewRetryAt time.Time
}

// NewManager loads saved State. A load failure is kept in LoadError and
// returned by every operation; nothing is written over the original.
func NewManager(client *Client, opts ManagerOptions) *Manager {
	if opts.TokenNamePrefix == "" {
		opts.TokenNamePrefix = "r2connect-"
	}
	if opts.CredentialLifetime == 0 {
		opts.CredentialLifetime = 30 * 24 * time.Hour
	}
	if opts.RenewalWindow == 0 {
		opts.RenewalWindow = 7 * 24 * time.Hour
	}
	if opts.ExpiryMargin == 0 {
		opts.ExpiryMargin = 5 * time.Minute
	}
	if opts.RenewalRetryDelay == 0 {
		opts.RenewalRetryDelay = time.Hour
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 16
	}
	m := &Manager{client: client, opts: opts}
	m.state, m.loadErr = LoadState(opts.State)
	if m.loadErr != nil {
		m.state = State{Version: 1, Connections: []Connection{}}
	}
	return m
}

func (m *Manager) LoadError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadErr
}

// State returns a copy of the current metadata.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.clone()
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	authorized := m.loadErr == nil && m.state.Authorized && m.state.ClientID == m.client.ClientID
	return Status{Authorized: authorized, Renewable: authorized && m.state.Renewable}
}

// OAuthSecretKey names the saved OAuth grant in the SecretStore.
func (m *Manager) OAuthSecretKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.oauthKey()
}

// CheckClient reports ErrClientChanged when connections or cleanup made with
// another OAuth client remain, since this client cannot remove them.
func (m *Manager) CheckClient() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.checkClientLocked()
}

func (m *Manager) checkClientLocked() error {
	if m.loadErr != nil {
		return m.loadErr
	}
	if m.state.ClientID != "" && m.state.ClientID != m.client.ClientID && (len(m.state.Connections) > 0 || len(m.state.RetiredTokens) > 0 || len(m.pendingRetired) > 0) {
		return ErrClientChanged
	}
	return nil
}

func (m *Manager) warn(warning Warning) {
	if m.opts.OnWarning != nil {
		m.opts.OnWarning(warning)
	}
}

func (m *Manager) saveLocked(next State) error {
	if m.loadErr != nil {
		return m.loadErr
	}
	next.RetiredTokens = append([]RetiredToken{}, next.RetiredTokens...)
	for _, retired := range m.pendingRetired {
		next.RetiredTokens = appendRetiredToken(next.RetiredTokens, retired)
	}
	if err := m.opts.State.Save(next); err != nil {
		return err
	}
	m.state = next
	m.pendingRetired = nil
	return nil
}

func (m *Manager) oauthKey() string {
	if m.state.OAuthCredentialKey != "" {
		return m.state.OAuthCredentialKey
	}
	return "oauth-" + m.client.ClientID
}

func appendRetiredToken(tokens []RetiredToken, token RetiredToken) []RetiredToken {
	for _, item := range tokens {
		if item == token {
			return tokens
		}
	}
	return append(tokens, token)
}

func (m *Manager) saveSecret(key string, value any) error {
	data, err := json.Marshal(value)
	if err == nil {
		err = m.opts.Secrets.Save(key, data)
	}
	clear(data)
	return err
}

func (m *Manager) tokensLocked(ctx context.Context) (TokenSet, error) {
	var tokens TokenSet
	if m.loadErr != nil {
		return tokens, m.loadErr
	}
	if !m.state.Authorized || m.state.ClientID != m.client.ClientID {
		return tokens, ErrNotAuthorized
	}
	if m.pendingTokens != nil {
		tokens = *m.pendingTokens
		if err := m.saveTokensLocked(tokens); err != nil {
			return TokenSet{}, err
		}
	} else {
		data, err := m.opts.Secrets.Load(m.oauthKey())
		if err != nil {
			return tokens, err
		}
		err = json.Unmarshal(data, &tokens)
		clear(data)
		if err != nil || tokens.AccessToken == "" || tokens.ExpiresAt.IsZero() {
			return TokenSet{}, ErrAuthorizationInvalid
		}
	}
	remaining := time.Until(tokens.ExpiresAt)
	if tokens.RefreshToken == "" {
		if remaining <= 0 {
			return TokenSet{}, ErrAuthorizationExpired
		}
	} else if remaining <= time.Minute {
		next, err := m.client.Refresh(ctx, tokens)
		if err != nil {
			return TokenSet{}, err
		}
		m.pendingTokens = &next
		if err = m.saveTokensLocked(next); err != nil {
			return TokenSet{}, err
		}
		tokens = next
	}
	if !tokens.HasScopes(RequiredScopes()...) {
		return TokenSet{}, ErrMissingScopes
	}
	return tokens, nil
}

func (m *Manager) saveTokensLocked(tokens TokenSet) error {
	if err := m.saveSecret(m.oauthKey(), tokens); err != nil {
		return err
	}
	m.pendingTokens = nil
	return nil
}

// Authorize saves a newly exchanged OAuth grant, replacing any previous one.
// A grant must cover every account that still has connections or cleanup, so
// those tokens stay removable. It commits nothing once ctx has ended.
func (m *Manager) Authorize(ctx context.Context, tokens TokenSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkClientLocked(); err != nil {
		return err
	}
	if !tokens.HasScopes(RequiredScopes()...) {
		return ErrMissingScopes
	}
	previousAccounts := make(map[string]bool)
	for _, connection := range m.state.Connections {
		previousAccounts[connection.AccountID] = true
	}
	for _, retired := range append(append([]RetiredToken{}, m.state.RetiredTokens...), m.pendingRetired...) {
		previousAccounts[retired.AccountID] = true
	}
	if len(previousAccounts) > 0 {
		accounts, err := m.client.Accounts(ctx, tokens.AccessToken)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			delete(previousAccounts, account.ID)
		}
		if len(previousAccounts) > 0 {
			return ErrAccountsMissing
		}
	}
	random, _, err := NewPKCE()
	if err != nil {
		return err
	}
	newKey := "oauth-" + random
	if err = m.saveSecret(newKey, tokens); err == nil {
		err = ctx.Err()
	}
	if err == nil {
		next := m.state.clone()
		next.ClientID, next.Authorized, next.OAuthCredentialKey, next.Renewable = m.client.ClientID, true, newKey, tokens.RefreshToken != ""
		next.RetiredOAuthKeys = append(next.RetiredOAuthKeys, m.oauthKey())
		err = m.saveLocked(next)
	}
	if err != nil {
		_ = m.opts.Secrets.Delete(newKey)
		return err
	}
	m.pendingTokens = nil
	m.revoked = false
	if err = m.cleanupOAuthKeysLocked(); err != nil {
		m.warn(WarningAuthorizationCleanup)
	}
	return nil
}

func (m *Manager) cleanupOAuthKeysLocked() error {
	for len(m.state.RetiredOAuthKeys) > 0 {
		key := m.state.RetiredOAuthKeys[0]
		if key == m.oauthKey() {
			return errors.New("refusing to remove the active Cloudflare authorization")
		}
		if err := m.opts.Secrets.Delete(key); err != nil {
			return err
		}
		next := m.state.clone()
		next.RetiredOAuthKeys = next.RetiredOAuthKeys[1:]
		if err := m.saveLocked(next); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Accounts(ctx context.Context) ([]Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tokens, err := m.tokensLocked(ctx)
	if err != nil {
		return nil, err
	}
	return m.client.Accounts(ctx, tokens.AccessToken)
}

func (m *Manager) Buckets(ctx context.Context, accountID, jurisdiction string) ([]Bucket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tokens, err := m.tokensLocked(ctx)
	if err != nil {
		return nil, err
	}
	return m.client.Buckets(ctx, tokens.AccessToken, accountID, jurisdiction)
}

// Connect provisions credentials restricted to one bucket and records them as
// a new connection. The bucket is verified with Cloudflare first, so a forged
// selection never gets credentials.
func (m *Manager) Connect(ctx context.Context, accountID, bucket, jurisdiction string) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := Endpoint(accountID, jurisdiction); err != nil {
		return Connection{}, err
	}
	tokens, err := m.tokensLocked(ctx)
	if err != nil {
		return Connection{}, err
	}
	buckets, err := m.client.Buckets(ctx, tokens.AccessToken, accountID, jurisdiction)
	if err != nil {
		return Connection{}, err
	}
	found := false
	for _, candidate := range buckets {
		if candidate.Name == bucket {
			found = true
			break
		}
	}
	if !found {
		return Connection{}, ErrBucketUnavailable
	}
	if len(m.state.Connections) >= m.opts.MaxConnections {
		return Connection{}, ErrTooManyConnections
	}
	id, _, err := NewPKCE()
	if err != nil {
		return Connection{}, err
	}
	// Every version gets its own secret. A failed metadata commit must never
	// replace the secret used by the previous, still-active connection.
	credentials, err := m.client.CreateCredentials(ctx, tokens.AccessToken, accountID, jurisdiction, bucket, m.opts.TokenNamePrefix+id[:12], time.Now().Add(m.opts.CredentialLifetime))
	if err != nil {
		return Connection{}, err
	}
	key := "connection-" + id + "-" + credentials.TokenID
	if err = m.saveSecret(key, credentials); err == nil {
		err = ctx.Err()
	}
	connection := Connection{ID: id, AccountID: accountID, Bucket: bucket, Jurisdiction: jurisdiction, TokenID: credentials.TokenID, ExpiresAt: credentials.ExpiresAt, CredentialKey: key}
	if err == nil {
		next := m.state.clone()
		next.Connections = append(next.Connections, connection)
		err = m.saveLocked(next)
	}
	if err != nil {
		m.compensateCredentialLocked(tokens.AccessToken, RetiredToken{AccountID: accountID, TokenID: credentials.TokenID, CredentialKey: key})
		return Connection{}, err
	}
	return connection, nil
}

func (m *Manager) rememberRetiredLocked(token RetiredToken) {
	next := m.state.clone()
	next.RetiredTokens = appendRetiredToken(next.RetiredTokens, token)
	if err := m.saveLocked(next); err != nil {
		m.pendingRetired = appendRetiredToken(m.pendingRetired, token)
	}
}

// A canceled request still compensates external mutations. If cleanup cannot
// complete, retain the token identifier so Disconnect can retry it later.
func (m *Manager) compensateCredentialLocked(accessToken string, token RetiredToken) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := m.client.DeleteToken(ctx, accessToken, token.AccountID, token.TokenID)
	if err == nil && token.CredentialKey != "" {
		err = m.opts.Secrets.Delete(token.CredentialKey)
	}
	if err != nil {
		m.rememberRetiredLocked(token)
		m.warn(WarningUnusedToken)
	}
}

func (m *Manager) cleanupRetiredLocked(ctx context.Context, accessToken string) error {
	if len(m.pendingRetired) > 0 {
		if err := m.saveLocked(m.state.clone()); err != nil {
			return err
		}
	}
	for len(m.state.RetiredTokens) > 0 {
		token := m.state.RetiredTokens[0]
		if err := m.client.DeleteToken(ctx, accessToken, token.AccountID, token.TokenID); err != nil {
			return err
		}
		if token.CredentialKey != "" {
			if err := m.opts.Secrets.Delete(token.CredentialKey); err != nil {
				return err
			}
		}
		next := m.state.clone()
		next.RetiredTokens = next.RetiredTokens[1:]
		if err := m.saveLocked(next); err != nil {
			return err
		}
	}
	return nil
}

// Credentials returns the S3 credentials of the connection matching want's ID,
// account, bucket and jurisdiction, renewing them when they are about to
// expire. A failed early renewal keeps returning the still-valid credentials.
func (m *Manager) Credentials(ctx context.Context, want Connection) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var credentials Credentials
	if m.loadErr != nil {
		return credentials, m.loadErr
	}
	index := -1
	for i, c := range m.state.Connections {
		if c.ID == want.ID && c.AccountID == want.AccountID && c.Bucket == want.Bucket && c.Jurisdiction == want.Jurisdiction {
			index = i
			break
		}
	}
	if index < 0 {
		return credentials, ErrUnknownConnection
	}
	connection := m.state.Connections[index]
	data, err := m.opts.Secrets.Load(connection.SecretKey())
	if err != nil {
		return credentials, err
	}
	err = json.Unmarshal(data, &credentials)
	clear(data)
	if err != nil || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.TokenID != connection.TokenID || credentials.ExpiresAt.IsZero() {
		return Credentials{}, ErrCredentialsInvalid
	}
	remaining := time.Until(credentials.ExpiresAt)
	if remaining > m.opts.ExpiryMargin && (!m.state.Renewable || remaining > m.opts.RenewalWindow || time.Now().Before(m.renewRetryAt)) {
		return credentials, nil
	}
	renewed, err := m.renewCredentialsLocked(ctx, index, connection)
	if err != nil && remaining > m.opts.ExpiryMargin {
		// Early renewal is best effort; current credentials keep working.
		m.renewRetryAt = time.Now().Add(m.opts.RenewalRetryDelay)
		return credentials, nil
	}
	if err == nil {
		m.renewRetryAt = time.Time{}
	}
	return renewed, err
}

func (m *Manager) renewCredentialsLocked(ctx context.Context, index int, connection Connection) (Credentials, error) {
	tokens, err := m.tokensLocked(ctx)
	if err != nil {
		return Credentials{}, err
	}
	credentials, err := m.client.CreateCredentials(ctx, tokens.AccessToken, connection.AccountID, connection.Jurisdiction, connection.Bucket, m.opts.TokenNamePrefix+connection.ID[:12], time.Now().Add(m.opts.CredentialLifetime))
	if err != nil {
		return Credentials{}, err
	}
	key := "connection-" + connection.ID + "-" + credentials.TokenID
	if err = m.saveSecret(key, credentials); err == nil {
		err = ctx.Err()
	}
	if err == nil {
		next := m.state.clone()
		next.Connections[index].TokenID, next.Connections[index].ExpiresAt, next.Connections[index].CredentialKey = credentials.TokenID, credentials.ExpiresAt, key
		next.RetiredTokens = appendRetiredToken(next.RetiredTokens, RetiredToken{AccountID: connection.AccountID, TokenID: connection.TokenID, CredentialKey: connection.SecretKey()})
		err = m.saveLocked(next)
	}
	if err != nil {
		m.compensateCredentialLocked(tokens.AccessToken, RetiredToken{AccountID: connection.AccountID, TokenID: credentials.TokenID, CredentialKey: key})
		return Credentials{}, err
	}
	if err = m.cleanupRetiredLocked(ctx, tokens.AccessToken); err != nil {
		m.warn(WarningRetiredToken)
	}
	return credentials, nil
}

// Discard removes one connection: its API token, then its saved credentials.
// Discarding an unknown connection succeeds.
func (m *Manager) Discard(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := -1
	for i, connection := range m.state.Connections {
		if connection.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	tokens, err := m.tokensLocked(ctx)
	if err != nil {
		return err
	}
	connection := m.state.Connections[index]
	if err = m.client.DeleteToken(ctx, tokens.AccessToken, connection.AccountID, connection.TokenID); err != nil {
		return err
	}
	if err = m.opts.Secrets.Delete(connection.SecretKey()); err != nil {
		return err
	}
	next := m.state.clone()
	next.Connections = append(next.Connections[:index], next.Connections[index+1:]...)
	return m.saveLocked(next)
}

// Disconnect removes every connection's API token and saved credentials,
// revokes the OAuth grant and forgets it. After a failure it can be retried:
// remote deletions are idempotent, and a grant already revoked is not used
// again.
func (m *Manager) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	if m.state.Authorized && !m.revoked {
		tokens, err := m.tokensLocked(ctx)
		if err != nil {
			return err
		}
		for len(m.state.Connections) > 0 {
			connection := m.state.Connections[0]
			if err = m.client.DeleteToken(ctx, tokens.AccessToken, connection.AccountID, connection.TokenID); err != nil {
				return fmt.Errorf("Could not remove an R2 token; authorization was kept so cleanup can be retried: %w", err)
			}
			// Keep the record until both remote and local deletion are complete.
			if err = m.opts.Secrets.Delete(connection.SecretKey()); err != nil {
				return err
			}
			next := m.state.clone()
			next.Connections = next.Connections[1:]
			if err = m.saveLocked(next); err != nil {
				return err
			}
		}
		if err = m.cleanupRetiredLocked(ctx, tokens.AccessToken); err != nil {
			return fmt.Errorf("Could not remove an older R2 token; authorization was kept so cleanup can be retried: %w", err)
		}
		if err = m.cleanupOAuthKeysLocked(); err != nil {
			return err
		}
		revocationToken := tokens.RefreshToken
		if revocationToken == "" {
			revocationToken = tokens.AccessToken
		}
		if err = m.client.Revoke(ctx, revocationToken); err != nil {
			return err
		}
		m.revoked = true
	}
	if len(m.state.Connections) > 0 || len(m.state.RetiredTokens) > 0 || len(m.pendingRetired) > 0 {
		return ErrCleanupPending
	}
	// If remote revocation succeeded but a local write failed, retries complete
	// locally instead of trying to refresh an already revoked refresh token.
	next := m.state.clone()
	next.Authorized = false
	err := m.saveLocked(next)
	if err == nil {
		err = m.cleanupOAuthKeysLocked()
	}
	if err == nil {
		err = m.opts.Secrets.Delete(m.oauthKey())
	}
	if err != nil {
		return err
	}
	m.pendingTokens = nil
	m.revoked = false
	return nil
}
