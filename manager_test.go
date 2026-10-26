package r2connect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAccount = "11111111111111111111111111111111"
	testBucket  = "r2connect-test"
)

type controlFixture struct {
	mu            sync.Mutex
	exchanges     int
	mints         int
	deletes       int
	revokes       int
	deleteStatus  int
	lastPolicy    map[string]any
	omitRefresh   bool
	expiresIn     int64
	revokedTokens []string
	accounts      []string
	// refreshFails makes refresh grants fail as for a grant revoked in the
	// dashboard.
	refreshFails bool
}

func (f *controlFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case req.Method == "POST" && req.URL.Path == "/oauth2/token":
		_ = req.ParseForm()
		f.mu.Lock()
		f.exchanges++
		omitRefresh, expiresIn, refreshFails := f.omitRefresh, f.expiresIn, f.refreshFails
		f.mu.Unlock()
		if refreshFails && req.Form.Get("grant_type") == "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		if expiresIn == 0 {
			expiresIn = 3600
		}
		response := map[string]any{"access_token": "synthetic-oauth-access", "expires_in": expiresIn, "token_type": "Bearer", "scope": OAuthScopes}
		if !omitRefresh {
			response["refresh_token"] = "synthetic-oauth-refresh"
		}
		_ = json.NewEncoder(w).Encode(response)
	case req.Method == "POST" && req.URL.Path == "/oauth2/revoke":
		_ = req.ParseForm()
		f.mu.Lock()
		f.revokes++
		f.revokedTokens = append(f.revokedTokens, req.Form.Get("token"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case req.URL.Path == "/client/v4/accounts" && req.Method == "GET":
		f.mu.Lock()
		accounts := f.accounts
		f.mu.Unlock()
		if accounts == nil {
			accounts = []string{testAccount}
		}
		var items []string
		for _, id := range accounts {
			items = append(items, `{"id":"`+id+`","name":"Isolated account"}`)
		}
		_, _ = io.WriteString(w, `{"success":true,"result":[`+strings.Join(items, ",")+`],"result_info":{"total_pages":1}}`)
	case req.URL.Path == "/client/v4/accounts/"+testAccount+"/r2/buckets" && req.Method == "GET":
		_, _ = io.WriteString(w, `{"success":true,"result":{"buckets":[{"name":"`+testBucket+`"}]}}`)
	case req.URL.Path == "/client/v4/accounts/"+testAccount+"/tokens/permission_groups" && req.Method == "GET":
		_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"33333333333333333333333333333333","name":"Workers R2 Storage Bucket Item Write","is_selectable":true,"scopes":["com.cloudflare.edge.r2.bucket"]}]}`)
	case req.URL.Path == "/client/v4/accounts/"+testAccount+"/tokens" && req.Method == "POST":
		var policy map[string]any
		if json.NewDecoder(req.Body).Decode(&policy) != nil {
			http.Error(w, "bad fixture request", 400)
			return
		}
		f.mu.Lock()
		f.mints++
		id := fmt.Sprintf("%032x", f.mints+100)
		f.lastPolicy = policy
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": id, "value": "synthetic-r2-token-" + id, "expires_on": policy["expires_on"]}})
	case strings.HasPrefix(req.URL.Path, "/client/v4/accounts/"+testAccount+"/tokens/") && req.Method == "DELETE":
		f.mu.Lock()
		f.deletes++
		status := f.deleteStatus
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000}]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": filepath.Base(req.URL.Path)}})
	default:
		http.Error(w, "unexpected isolated Cloudflare request", 404)
	}
}

func (f *controlFixture) set(change func(*controlFixture)) {
	f.mu.Lock()
	change(f)
	f.mu.Unlock()
}

func (f *controlFixture) counts() (exchanges, mints, deletes, revokes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges, f.mints, f.deletes, f.revokes
}

type memorySecrets struct {
	mu       sync.Mutex
	items    map[string][]byte
	saveFail func(key string) error
	delFail  func(key string) error
}

func (s *memorySecrets) Load(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.items[key]
	if !ok {
		return nil, errors.New("synthetic secret not found")
	}
	return bytes.Clone(value), nil
}

func (s *memorySecrets) Save(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveFail != nil {
		if err := s.saveFail(key); err != nil {
			return err
		}
	}
	s.items[key] = bytes.Clone(value)
	return nil
}

func (s *memorySecrets) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delFail != nil {
		if err := s.delFail(key); err != nil {
			return err
		}
	}
	delete(s.items, key)
	return nil
}

func (s *memorySecrets) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func (s *memorySecrets) edit(t *testing.T, key string, value any, change func()) {
	t.Helper()
	data, err := s.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
	change()
	if data, err = json.Marshal(value); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(key, data); err != nil {
		t.Fatal(err)
	}
}

// failingState fails saves while fail is set.
type failingState struct {
	FileStateStore
	mu   sync.Mutex
	fail error
}

func (s *failingState) Save(state State) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail != nil {
		return fail
	}
	return s.FileStateStore.Save(state)
}

func (s *failingState) setFail(err error) {
	s.mu.Lock()
	s.fail = err
	s.mu.Unlock()
}

type managerFixture struct {
	m        *Manager
	control  *controlFixture
	secrets  *memorySecrets
	state    *failingState
	client   *Client
	warnings []Warning
}

func newManagerFixture(t *testing.T) *managerFixture {
	t.Helper()
	control := &controlFixture{}
	server := httptest.NewServer(control)
	t.Cleanup(server.Close)
	client := NewClient("synthetic-client")
	client.APIBaseURL, client.OAuthBaseURL = server.URL+"/client/v4", server.URL+"/oauth2"
	f := &managerFixture{control: control, secrets: &memorySecrets{items: map[string][]byte{}}, state: &failingState{FileStateStore: FileStateStore{Path: filepath.Join(t.TempDir(), "state.json")}}, client: client}
	f.m = NewManager(client, ManagerOptions{Secrets: f.secrets, State: f.state, OnWarning: func(w Warning) { f.warnings = append(f.warnings, w) }})
	return f
}

func (f *managerFixture) authorize(t *testing.T) {
	t.Helper()
	tokens, err := f.client.ExchangeCode(t.Context(), "synthetic-code", "http://localhost:18796/callback", strings.Repeat("v", 43))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.m.Authorize(t.Context(), tokens); err != nil {
		t.Fatal(err)
	}
	if !f.m.Status().Authorized {
		t.Fatal("authorization was not saved")
	}
}

func (f *managerFixture) connect(t *testing.T) Connection {
	t.Helper()
	connection, err := f.m.Connect(t.Context(), testAccount, testBucket, "default")
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func (f *managerFixture) expireOAuth(t *testing.T) {
	t.Helper()
	var tokens TokenSet
	f.secrets.edit(t, f.m.OAuthSecretKey(), &tokens, func() { tokens.ExpiresAt = time.Now().Add(-time.Minute) })
}

func (f *managerFixture) setCredentialExpiry(t *testing.T, expiresAt time.Time) Credentials {
	t.Helper()
	var credentials Credentials
	f.secrets.edit(t, f.m.State().Connections[0].SecretKey(), &credentials, func() { credentials.ExpiresAt = expiresAt })
	return credentials
}

func TestManagerProvisionsBucketScopedCredentials(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	accounts, err := f.m.Accounts(t.Context())
	if err != nil || len(accounts) != 1 || accounts[0].ID != testAccount {
		t.Fatalf("account enumeration failed: %v", err)
	}
	buckets, err := f.m.Buckets(t.Context(), testAccount, "default")
	if err != nil || len(buckets) != 1 {
		t.Fatalf("bucket enumeration failed: %v", err)
	}
	connection := f.connect(t)
	credentials, err := f.m.Credentials(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte("synthetic-r2-token-" + credentials.AccessKeyID))
	if credentials.SecretAccessKey != hex.EncodeToString(expected[:]) {
		t.Fatal("credentials were not derived from the API token")
	}
	f.control.mu.Lock()
	policy := f.control.lastPolicy
	f.control.mu.Unlock()
	policies := policy["policies"].([]any)
	resources := policies[0].(map[string]any)["resources"].(map[string]any)
	if len(policies) != 1 || len(resources) != 1 || resources["com.cloudflare.edge.r2.bucket."+testAccount+"_default_"+testBucket] != "*" {
		t.Fatal("provisioned token was not restricted to the chosen bucket")
	}
	if !strings.HasPrefix(policy["name"].(string), "r2connect-") {
		t.Fatal("API token did not use the default name prefix")
	}
	disk, err := os.ReadFile(f.state.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"synthetic-oauth-access", "synthetic-oauth-refresh", credentials.SecretAccessKey} {
		if bytes.Contains(disk, []byte(secret)) {
			t.Fatal("secrets entered the state file")
		}
	}
	forged := connection
	forged.Bucket = "another-bucket"
	if _, err = f.m.Credentials(t.Context(), forged); !errors.Is(err, ErrUnknownConnection) {
		t.Fatal("a mismatched connection selector returned credentials")
	}
	if _, err = f.m.Connect(t.Context(), testAccount, "another-bucket", "default"); !errors.Is(err, ErrBucketUnavailable) {
		t.Fatal("a bucket Cloudflare did not list was provisioned")
	}
}

func TestManagerReopensSavedState(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	connection := f.connect(t)
	reopened := NewManager(f.client, ManagerOptions{Secrets: f.secrets, State: f.state.FileStateStore})
	if err := reopened.LoadError(); err != nil || !reopened.Status().Authorized {
		t.Fatalf("reopening lost the authorization: %v", err)
	}
	if _, err := reopened.Credentials(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
}

func TestManagerPreservesUnreadableState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, data := range []string{`{"version":2}`, `{"version":1,"connections":[{"id":"short"}]}`, `not json`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		m := NewManager(NewClient("synthetic-client"), ManagerOptions{Secrets: &memorySecrets{items: map[string][]byte{}}, State: FileStateStore{Path: path}})
		if !errors.Is(m.LoadError(), ErrInvalidState) {
			t.Fatalf("invalid state %q was not reported as ErrInvalidState: %v", data, m.LoadError())
		}
		if err := m.Disconnect(t.Context()); err == nil {
			t.Fatal("an operation ran on unreadable state")
		}
		if after, _ := os.ReadFile(path); string(after) != data {
			t.Fatal("unreadable state was overwritten")
		}
	}
}

func TestManagerAuthorizeChecks(t *testing.T) {
	f := newManagerFixture(t)
	if err := f.m.Authorize(t.Context(), TokenSet{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour), Scope: "account-settings.read"}); !errors.Is(err, ErrMissingScopes) {
		t.Fatalf("partial scopes were accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.m.Authorize(ctx, TokenSet{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour), Scope: OAuthScopes}); !errors.Is(err, context.Canceled) || f.m.Status().Authorized || f.secrets.len() != 0 {
		t.Fatal("a canceled authorization was saved")
	}
	f.authorize(t)
	f.connect(t)
	f.control.set(func(c *controlFixture) { c.accounts = []string{strings.Repeat("2", 32)} })
	if err := f.m.Authorize(t.Context(), TokenSet{AccessToken: "other", ExpiresAt: time.Now().Add(time.Hour), Scope: OAuthScopes}); !errors.Is(err, ErrAccountsMissing) {
		t.Fatalf("a grant without the connected account replaced the authorization: %v", err)
	}
	other := NewManager(NewClient("another-client"), ManagerOptions{Secrets: f.secrets, State: f.state.FileStateStore})
	if err := other.CheckClient(); !errors.Is(err, ErrClientChanged) {
		t.Fatal("a different OAuth client was allowed to take over existing connections")
	}
	if other.Status().Authorized {
		t.Fatal("another client's authorization was reported as usable")
	}
}

func TestManagerReauthorizationReplacesSecret(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	first := f.m.OAuthSecretKey()
	f.authorize(t)
	if second := f.m.OAuthSecretKey(); second == first || f.secrets.len() != 1 || len(f.m.State().RetiredOAuthKeys) != 0 {
		t.Fatal("reauthorization did not replace and clean up the previous grant")
	}
	f.secrets.delFail = func(string) error { return errors.New("synthetic cleanup failure") }
	f.authorize(t)
	if len(f.warnings) != 1 || f.warnings[0] != WarningAuthorizationCleanup || len(f.m.State().RetiredOAuthKeys) != 1 {
		t.Fatal("a failed cleanup of the previous grant was not reported and remembered")
	}
}

func TestManagerCodeOnlyGrantKeepsCredentialsAfterAuthorizationExpires(t *testing.T) {
	f := newManagerFixture(t)
	f.control.set(func(c *controlFixture) { c.omitRefresh = true })
	f.authorize(t)
	if f.m.State().Renewable {
		t.Fatal("a code-only grant was recorded as renewable")
	}
	connection := f.connect(t)
	f.expireOAuth(t)
	if _, err := f.m.Credentials(t.Context(), connection); err != nil {
		t.Fatal("valid S3 credentials incorrectly required a live OAuth token:", err)
	}
	if _, err := f.m.Accounts(t.Context()); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired code-only grant did not request reauthorization: %v", err)
	}
	if err := f.m.Disconnect(t.Context()); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired code-only grant attempted remote cleanup: %v", err)
	}
	if exchanges, _, deletes, _ := f.control.counts(); exchanges != 1 || deletes != 0 {
		t.Fatal("expired code-only management modified credentials or attempted a refresh")
	}
	f.authorize(t)
	if err := f.m.Disconnect(t.Context()); err != nil {
		t.Fatal("reauthorized code-only disconnect failed:", err)
	}
	f.control.mu.Lock()
	revoked := append([]string{}, f.control.revokedTokens...)
	f.control.mu.Unlock()
	if len(revoked) != 1 || revoked[0] != "synthetic-oauth-access" {
		t.Fatal("disconnect did not explicitly revoke the access token from the code-only grant")
	}
}

func TestManagerCodeOnlyShortLivedTokenRemainsUsable(t *testing.T) {
	f := newManagerFixture(t)
	f.control.set(func(c *controlFixture) { c.omitRefresh, c.expiresIn = true, 30 })
	f.authorize(t)
	if accounts, err := f.m.Accounts(t.Context()); err != nil || len(accounts) != 1 {
		t.Fatalf("a still-valid code-only token was treated as expired: %v", err)
	}
	if exchanges, _, _, _ := f.control.counts(); exchanges != 1 {
		t.Fatal("a short-lived code-only token triggered an unsupported refresh")
	}
}

func TestManagerProvisioningFailureRemovesNewToken(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	failure := errors.New("synthetic credential-store write failure")
	oauthKey := f.m.OAuthSecretKey()
	f.secrets.saveFail = func(key string) error {
		if key != oauthKey {
			return failure
		}
		return nil
	}
	if _, err := f.m.Connect(t.Context(), testAccount, testBucket, "default"); !errors.Is(err, failure) {
		t.Fatal("provisioning did not report that the new credentials could not be saved")
	}
	if _, mints, deletes, _ := f.control.counts(); mints != 1 || deletes != 1 || len(f.m.State().Connections) != 0 {
		t.Fatal("failed setup left an untracked remote R2 credential")
	}
	if f.secrets.len() != 1 || !f.m.Status().Authorized {
		t.Fatal("failed setup discarded the reusable OAuth authorization")
	}
}

func TestManagerRotatingRefreshRecoversFromSecretStoreFailure(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	f.expireOAuth(t)
	failure := errors.New("synthetic rotating-token save failure")
	key, remaining := f.m.OAuthSecretKey(), 1
	f.secrets.saveFail = func(saved string) error {
		if saved == key && remaining > 0 {
			remaining--
			return failure
		}
		return nil
	}
	if _, err := f.m.Accounts(t.Context()); !errors.Is(err, failure) {
		t.Fatal("failed refresh-token save was not reported")
	}
	if exchanges, _, _, _ := f.control.counts(); exchanges != 2 {
		t.Fatal("expired OAuth credentials did not refresh exactly once")
	}
	if _, err := f.m.Accounts(t.Context()); err != nil {
		t.Fatal("a transient secret-store failure prevented recovery:", err)
	}
	if exchanges, _, _, _ := f.control.counts(); exchanges != 2 {
		t.Fatal("retry reused the already-consumed rotating refresh token")
	}
	if f.m.pendingTokens != nil {
		t.Fatal("successfully saved replacement tokens remained pending")
	}
}

func TestManagerRotationMetadataFailureKeepsPreviousCredentials(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	connection := f.connect(t)
	previous := f.setCredentialExpiry(t, time.Now().Add(time.Minute))
	before, _ := f.secrets.Load(connection.SecretKey())
	failure := errors.New("synthetic rotation metadata write failure")
	f.state.setFail(failure)
	if _, err := f.m.Credentials(t.Context(), connection); !errors.Is(err, failure) {
		t.Fatal("rotation metadata failure was not reported")
	}
	after, err := f.secrets.Load(connection.SecretKey())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed rotation overwrote the previous usable credentials")
	}
	if state := f.m.State(); state.Connections[0].TokenID != previous.TokenID || state.Connections[0].SecretKey() != connection.SecretKey() {
		t.Fatal("failed rotation changed the active credential metadata")
	}
	if _, mints, deletes, _ := f.control.counts(); mints != 2 || deletes != 1 || f.secrets.len() != 2 {
		t.Fatal("failed rotation did not compensate only the newly created credential")
	}
	f.state.setFail(nil)
	if _, err = f.m.Credentials(t.Context(), connection); err != nil {
		t.Fatal("retry did not recover after a metadata write failure:", err)
	}
	if f.m.State().Connections[0].TokenID == previous.TokenID {
		t.Fatal("successful retry did not install replacement credentials")
	}
}

func TestManagerDisconnectRetriesRemoteCleanup(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	f.connect(t)
	f.control.set(func(c *controlFixture) { c.deleteStatus = http.StatusServiceUnavailable })
	if err := f.m.Disconnect(t.Context()); err == nil {
		t.Fatal("failed remote token deletion was reported as a successful disconnect")
	}
	if _, _, _, revokes := f.control.counts(); !f.m.Status().Authorized || len(f.m.State().Connections) != 1 || f.secrets.len() != 2 || revokes != 0 {
		t.Fatal("failed cleanup discarded the authorization needed for retry")
	}
	f.control.set(func(c *controlFixture) { c.deleteStatus = 0 })
	if err := f.m.Disconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.m.Status().Authorized || len(f.m.State().Connections) != 0 || f.secrets.len() != 0 {
		t.Fatal("disconnect did not remove remote credential metadata and local secrets")
	}
	if _, _, deletes, revokes := f.control.counts(); deletes != 2 || revokes != 1 {
		t.Fatal("disconnect did not delete the dedicated R2 token before revoking OAuth")
	}
}

func TestManagerDiscardRetriesAndIsIdempotent(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	saved := f.connect(t)
	candidate := f.connect(t)
	f.control.set(func(c *controlFixture) { c.deleteStatus = http.StatusServiceUnavailable })
	if err := f.m.Discard(t.Context(), candidate.ID); err == nil {
		t.Fatal("failed candidate deletion was reported as success")
	}
	if len(f.m.State().Connections) != 2 || f.secrets.len() != 3 {
		t.Fatal("failed candidate deletion discarded cleanup information")
	}
	f.control.set(func(c *controlFixture) { c.deleteStatus = 0 })
	if err := f.m.Discard(t.Context(), candidate.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Discard(t.Context(), candidate.ID); err != nil {
		t.Fatal("discarding an absent candidate was not idempotent:", err)
	}
	if state := f.m.State(); len(state.Connections) != 1 || state.Connections[0].ID != saved.ID || f.secrets.len() != 2 {
		t.Fatal("discarding a candidate changed the other connection")
	}
}

func TestManagerRetiredCredentialCleanupCanRetryAfterRotation(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	connection := f.connect(t)
	f.setCredentialExpiry(t, time.Now().Add(time.Minute))
	f.control.set(func(c *controlFixture) { c.deleteStatus = http.StatusServiceUnavailable })
	renewed, err := f.m.Credentials(t.Context(), connection)
	if err != nil || renewed.TokenID == connection.TokenID {
		t.Fatal("failed old-token cleanup prevented using newly committed credentials:", err)
	}
	if state := f.m.State(); len(state.RetiredTokens) != 1 || state.RetiredTokens[0].TokenID != connection.TokenID || f.secrets.len() != 3 {
		t.Fatal("rotation forgot the old credential after its remote deletion failed")
	}
	if len(f.warnings) != 1 || f.warnings[0] != WarningRetiredToken {
		t.Fatalf("failed old-token cleanup was not reported: %v", f.warnings)
	}
	f.control.set(func(c *controlFixture) { c.deleteStatus = 0 })
	if err = f.m.Disconnect(t.Context()); err != nil {
		t.Fatal("disconnect could not retry old-token cleanup:", err)
	}
	if state := f.m.State(); len(state.RetiredTokens) != 0 || len(state.Connections) != 0 || f.secrets.len() != 0 {
		t.Fatal("disconnect left retired credentials behind")
	}
}

func TestManagerDisconnectMetadataFailureDoesNotReuseRevokedAuthorization(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	failure := errors.New("synthetic post-revocation metadata failure")
	f.state.setFail(failure)
	if err := f.m.Disconnect(t.Context()); !errors.Is(err, failure) {
		t.Fatal("post-revocation persistence failure was not reported")
	}
	// Even if the saved access token expires before retry, remote revocation
	// already succeeded. Finishing local cleanup must not refresh it again.
	f.expireOAuth(t)
	f.state.setFail(nil)
	if err := f.m.Disconnect(t.Context()); err != nil {
		t.Fatal("local cleanup retried an already revoked OAuth authorization:", err)
	}
	if exchanges, _, _, revokes := f.control.counts(); exchanges != 1 || revokes != 1 || f.secrets.len() != 0 || f.m.Status().Authorized {
		t.Fatal("disconnect reused a revoked token or left local authorization active")
	}
}

func TestManagerRefreshableGrantRenewsCredentialsEarly(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	if !f.m.State().Renewable {
		t.Fatal("a grant with a refresh token was not recorded as renewable")
	}
	connection := f.connect(t)
	if _, err := f.m.Credentials(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	if _, mints, _, _ := f.control.counts(); mints != 1 {
		t.Fatal("fresh credentials were renewed")
	}
	// Inside the renewal window, an expired access token is refreshed and the
	// bucket credentials are replaced without a browser.
	previous := f.setCredentialExpiry(t, time.Now().Add(3*24*time.Hour))
	f.expireOAuth(t)
	renewed, err := f.m.Credentials(t.Context(), connection)
	if err != nil {
		t.Fatal("silent renewal failed:", err)
	}
	if exchanges, mints, deletes, _ := f.control.counts(); exchanges != 2 || mints != 2 || deletes != 1 || renewed.AccessKeyID == previous.AccessKeyID || f.m.State().Connections[0].TokenID == previous.TokenID {
		t.Fatalf("silent renewal did not refresh, rotate and retire: exchanges=%d mints=%d deletes=%d", exchanges, mints, deletes)
	}
	// A failed early renewal keeps the still-valid credentials and backs off.
	current := f.setCredentialExpiry(t, time.Now().Add(3*24*time.Hour))
	if err = f.secrets.Save(f.m.OAuthSecretKey(), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		used, err := f.m.Credentials(t.Context(), connection)
		if err != nil || used.AccessKeyID != current.AccessKeyID {
			t.Fatal("a failed early renewal interrupted use of valid credentials:", err)
		}
	}
	if f.m.renewRetryAt[connection.ID].IsZero() {
		t.Fatal("a failed early renewal did not back off")
	}
	f.setCredentialExpiry(t, time.Now().Add(time.Minute))
	if _, err = f.m.Credentials(t.Context(), connection); err == nil {
		t.Fatal("expiring credentials were used after renewal failed")
	}
}

func TestManagerCodeOnlyGrantRenewsOnlyNearExpiry(t *testing.T) {
	f := newManagerFixture(t)
	f.control.set(func(c *controlFixture) { c.omitRefresh = true })
	f.authorize(t)
	connection := f.connect(t)
	f.setCredentialExpiry(t, time.Now().Add(3*24*time.Hour))
	if _, err := f.m.Credentials(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	if _, mints, _, _ := f.control.counts(); mints != 1 {
		t.Fatal("a code-only grant renewed credentials early")
	}
}

func TestManagerRejectsInvalidOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	saved := `{"version":1,"connections":[]}`
	if err := os.WriteFile(path, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	secrets := &memorySecrets{items: map[string][]byte{}}
	valid := func() ManagerOptions { return ManagerOptions{Secrets: secrets, State: FileStateStore{Path: path}} }
	cases := map[string]func(*ManagerOptions){
		"missing secrets":        func(o *ManagerOptions) { o.Secrets = nil },
		"missing state":          func(o *ManagerOptions) { o.State = nil },
		"negative duration":      func(o *ManagerOptions) { o.RenewalRetryDelay = -time.Second },
		"negative connections":   func(o *ManagerOptions) { o.MaxConnections = -1 },
		"lifetime inside window": func(o *ManagerOptions) { o.CredentialLifetime = 24 * time.Hour },
		"lifetime equals window": func(o *ManagerOptions) { o.CredentialLifetime, o.RenewalWindow = time.Hour, time.Hour },
		"lifetime inside margin": func(o *ManagerOptions) {
			o.CredentialLifetime, o.RenewalWindow, o.ExpiryMargin = 5*time.Minute, time.Minute, 5*time.Minute
		},
		"token name prefix too long": func(o *ManagerOptions) { o.TokenNamePrefix = strings.Repeat("p", maxTokenNamePrefix+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			opts := valid()
			change(&opts)
			m := NewManager(NewClient("synthetic-client"), opts)
			if !errors.Is(m.LoadError(), ErrInvalidOptions) {
				t.Fatalf("invalid options were accepted: %v", m.LoadError())
			}
			if err := m.Authorize(t.Context(), TokenSet{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour), Scope: OAuthScopes}); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("an operation ran with invalid options: %v", err)
			}
			if _, err := m.Forget(); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("Forget ran with invalid options: %v", err)
			}
			if after, _ := os.ReadFile(path); string(after) != saved || secrets.len() != 0 {
				t.Fatal("a Manager with invalid options wrote state or secrets")
			}
		})
	}
	opts := valid()
	opts.CredentialLifetime, opts.RenewalWindow, opts.ExpiryMargin = time.Hour, 30*time.Minute, time.Minute
	opts.TokenNamePrefix = strings.Repeat("p", maxTokenNamePrefix)
	if err := NewManager(NewClient("synthetic-client"), opts).LoadError(); err != nil {
		t.Fatal("consistent custom options were rejected:", err)
	}
}

func TestManagerForgetClearsWhenDisconnectCannotFinish(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	original := f.connect(t)
	// A rotation whose old-token deletion fails leaves pending cleanup too.
	f.setCredentialExpiry(t, time.Now().Add(time.Minute))
	f.control.set(func(c *controlFixture) { c.deleteStatus = http.StatusServiceUnavailable })
	if _, err := f.m.Credentials(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	current := f.m.State().Connections[0]
	// The grant is then revoked in the dashboard, so nothing remote can run.
	f.control.set(func(c *controlFixture) { c.deleteStatus, c.refreshFails = 0, true })
	f.expireOAuth(t)
	if err := f.m.Disconnect(t.Context()); err == nil || !f.m.Status().Authorized {
		t.Fatal("Disconnect finished without a usable grant")
	}
	_, mints, deletes, revokes := f.control.counts()

	failure := errors.New("synthetic secret deletion failure")
	f.secrets.delFail = func(string) error { return failure }
	if _, err := f.m.Forget(); !errors.Is(err, failure) || len(f.m.State().Connections) != 1 {
		t.Fatal("a failed Forget cleared State before removing secrets:", err)
	}
	f.secrets.delFail = nil
	orphans, err := f.m.Forget()
	if err != nil {
		t.Fatal(err)
	}
	want := []RetiredToken{{AccountID: testAccount, TokenID: current.TokenID}, {AccountID: testAccount, TokenID: original.TokenID}}
	if fmt.Sprint(orphans) != fmt.Sprint(want) {
		t.Fatalf("Forget reported %v, want %v", orphans, want)
	}
	if _, m2, d2, r2 := f.control.counts(); m2 != mints || d2 != deletes || r2 != revokes {
		t.Fatal("Forget contacted Cloudflare")
	}
	state := f.m.State()
	if f.secrets.len() != 0 || state.Authorized || state.ClientID != "" || len(state.Connections) != 0 || len(state.RetiredTokens) != 0 || f.m.Status().Authorized {
		t.Fatalf("Forget left local data behind: secrets=%d state=%+v", f.secrets.len(), state)
	}
	reopened := NewManager(f.client, ManagerOptions{Secrets: f.secrets, State: f.state.FileStateStore})
	if err = reopened.LoadError(); err != nil || len(reopened.State().Connections) != 0 {
		t.Fatal("Forget did not persist the cleared State:", err)
	}
	// A grant for different accounts is accepted again.
	f.control.set(func(c *controlFixture) { c.accounts, c.refreshFails = []string{strings.Repeat("2", 32)}, false })
	f.authorize(t)
}

func TestManagerDisconnectWithChangedClient(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	connection := f.connect(t)
	other := NewManager(NewClient("another-client"), ManagerOptions{Secrets: f.secrets, State: f.state})
	if err := other.Disconnect(t.Context()); !errors.Is(err, ErrClientChanged) {
		t.Fatalf("Disconnect with another client reported %v", err)
	}
	if err := other.Discard(t.Context(), connection.ID); !errors.Is(err, ErrClientChanged) {
		t.Fatalf("Discard with another client reported %v", err)
	}
	if err := f.m.Discard(t.Context(), connection.ID); err != nil {
		t.Fatal(err)
	}
	// With nothing left to clean up remotely, the old grant is forgotten
	// locally without using the other client.
	other = NewManager(NewClient("another-client"), ManagerOptions{Secrets: f.secrets, State: f.state})
	_, _, _, revokes := f.control.counts()
	if err := other.Disconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, after := f.control.counts(); after != revokes || f.secrets.len() != 0 || other.State().Authorized {
		t.Fatal("Disconnect did not forget the other client's grant locally")
	}
}

func TestManagerRenewalBackoffIsPerConnection(t *testing.T) {
	f := newManagerFixture(t)
	f.authorize(t)
	first, second := f.connect(t), f.connect(t)
	for _, connection := range []Connection{first, second} {
		var credentials Credentials
		f.secrets.edit(t, connection.SecretKey(), &credentials, func() { credentials.ExpiresAt = time.Now().Add(3 * 24 * time.Hour) })
	}
	f.control.set(func(c *controlFixture) { c.refreshFails = true })
	f.expireOAuth(t)
	if _, err := f.m.Credentials(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if f.m.renewRetryAt[first.ID].IsZero() || !f.m.renewRetryAt[second.ID].IsZero() {
		t.Fatal("a failed renewal of one connection delayed the others")
	}
	f.control.set(func(c *controlFixture) { c.refreshFails = false })
	renewed, err := f.m.Credentials(t.Context(), second)
	if err != nil || renewed.TokenID == second.TokenID {
		t.Fatal("another connection did not renew while the first backed off:", err)
	}
}
