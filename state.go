package r2connect

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidState reports saved Manager metadata that cannot be used. The
// original is left in place so it can be recovered. Every validation failure
// matches it with errors.Is.
var ErrInvalidState = errors.New("invalid Cloudflare authorization metadata")

// stateError keeps a specific message while matching ErrInvalidState.
type stateError string

func (e stateError) Error() string        { return string(e) }
func (e stateError) Is(target error) bool { return target == ErrInvalidState }

const maxStateBytes = 64 << 10

// State is the Manager's non-secret metadata. Secrets live in the SecretStore
// under the keys it names.
type State struct {
	Version            int            `json:"version"`
	ClientID           string         `json:"clientId"`
	Authorized         bool           `json:"authorized"`
	Connections        []Connection   `json:"connections"`
	RetiredTokens      []RetiredToken `json:"retiredTokens,omitempty"`
	OAuthCredentialKey string         `json:"oauthCredentialKey,omitempty"`
	// Renewable records that the saved grant has a refresh token, so callers
	// can decide on early renewal without reading the OAuth secret.
	Renewable        bool     `json:"renewable,omitempty"`
	RetiredOAuthKeys []string `json:"retiredOAuthKeys,omitempty"`
}

// Connection is one bucket with its own expiring, bucket-scoped API token.
type Connection struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"accountId"`
	Bucket        string    `json:"bucket"`
	Jurisdiction  string    `json:"jurisdiction"`
	TokenID       string    `json:"tokenId"`
	ExpiresAt     time.Time `json:"expiresAt"`
	CredentialKey string    `json:"credentialKey,omitempty"`
}

// SecretKey names the connection's credentials in the SecretStore.
func (c Connection) SecretKey() string {
	if c.CredentialKey != "" {
		return c.CredentialKey
	}
	return "connection-" + c.ID
}

// RetiredToken is a replaced or abandoned API token whose remote deletion is
// still pending.
type RetiredToken struct {
	AccountID     string `json:"accountId"`
	TokenID       string `json:"tokenId"`
	CredentialKey string `json:"credentialKey,omitempty"`
}

func (s State) clone() State {
	s.Connections = append([]Connection{}, s.Connections...)
	s.RetiredTokens = append([]RetiredToken(nil), s.RetiredTokens...)
	s.RetiredOAuthKeys = append([]string(nil), s.RetiredOAuthKeys...)
	return s
}

// StateStore persists State. Load returns ok false when nothing is saved yet.
type StateStore interface {
	Load() (state State, ok bool, err error)
	Save(State) error
}

// FileStateStore keeps State in a JSON file, replaced atomically on save.
type FileStateStore struct{ Path string }

func (f FileStateStore) Load() (State, bool, error) {
	var state State
	info, err := os.Lstat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return state, false, ErrInvalidState
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return state, false, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, false, ErrInvalidState
	}
	return state, true, nil
}

func (f FileStateStore) Save(state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxStateBytes {
		return errors.New("Cloudflare authorization metadata is too large")
	}
	file, err := os.CreateTemp(filepath.Dir(f.Path), ".r2-oauth-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(file.Name(), f.Path); err != nil {
		return err
	}
	// Persist the rename itself. Not every platform can sync a directory, so
	// this is best effort.
	if dir, err := os.Open(filepath.Dir(f.Path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// LoadState reads and validates saved State. Without saved State it returns
// an empty, valid State.
func LoadState(store StateStore) (State, error) {
	state, ok, err := store.Load()
	if err != nil {
		return State{}, err
	}
	if !ok {
		return emptyState(), nil
	}
	if err = validateState(state); err != nil {
		return State{}, err
	}
	if state.Connections == nil {
		state.Connections = []Connection{}
	}
	return state, nil
}

func validSecretKey(key string) bool {
	return key != "" && len(key) <= 128 && utf8.ValidString(key) && !strings.ContainsRune(key, '\x00')
}

func emptyState() State {
	return State{Version: 1, Connections: []Connection{}}
}

func validateState(state State) error {
	if state.Version != 1 {
		return stateError("unsupported Cloudflare authorization metadata")
	}
	if state.Authorized && (state.ClientID == "" || len(state.ClientID) > 256 || strings.ContainsAny(state.ClientID, " \t\r\n")) {
		return ErrInvalidState
	}
	if state.OAuthCredentialKey != "" && (!validSecretKey(state.OAuthCredentialKey) || !strings.HasPrefix(state.OAuthCredentialKey, "oauth-")) {
		return ErrInvalidState
	}
	for _, key := range state.RetiredOAuthKeys {
		if !validSecretKey(key) || !strings.HasPrefix(key, "oauth-") {
			return stateError("invalid Cloudflare authorization cleanup metadata")
		}
	}
	seen := make(map[string]bool)
	for _, connection := range state.Connections {
		key := connection.SecretKey()
		if len(connection.ID) < 12 || len(connection.ID) > 80 || strings.ContainsAny(connection.ID, " /\\\x00\r\n\t") || seen[connection.ID] || connection.Bucket == "" || connection.ExpiresAt.IsZero() || !validID(connection.TokenID) || !validSecretKey(key) || !strings.HasPrefix(key, "connection-") {
			return stateError("invalid Cloudflare connection metadata")
		}
		if _, err := Endpoint(connection.AccountID, connection.Jurisdiction); err != nil {
			return stateError("invalid Cloudflare connection metadata")
		}
		seen[connection.ID] = true
	}
	for _, retired := range state.RetiredTokens {
		if !validID(retired.TokenID) || retired.CredentialKey != "" && (!validSecretKey(retired.CredentialKey) || !strings.HasPrefix(retired.CredentialKey, "connection-")) {
			return stateError("invalid Cloudflare credential cleanup metadata")
		}
		if _, err := Endpoint(retired.AccountID, "default"); err != nil {
			return stateError("invalid Cloudflare credential cleanup metadata")
		}
	}
	return nil
}
