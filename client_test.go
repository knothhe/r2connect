package r2connect

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	accountID    = "0123456789abcdef0123456789abcdef"
	tokenID      = "fedcba9876543210fedcba9876543210"
	permissionID = "1234567890abcdef1234567890abcdef"
	callback     = "http://localhost:18796/oauth/cloudflare/callback"
	verifier     = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := NewClient("test-client")
	client.APIBaseURL, client.OAuthBaseURL = server.URL+"/v4", server.URL+"/oauth2"
	return client
}

func jsonResponse(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func apiResponse(w http.ResponseWriter, result any, info any) {
	jsonResponse(w, map[string]any{"success": true, "result": result, "result_info": info})
}

func TestAuthorizationUsesPKCEAndIndependentState(t *testing.T) {
	client := NewClient("own-client")
	value, err := client.AuthorizationURL(callback, "state", verifier)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(value)
	if u.Scheme != "https" || u.Host != "dash.cloudflare.com" || u.Path != "/oauth2/auth" {
		t.Fatalf("unexpected endpoint: %s", u)
	}
	query := u.Query()
	if query.Get("code_challenge") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" || query.Get("code_challenge_method") != "S256" || query.Get("state") != "state" || query.Get("redirect_uri") != callback || query.Get("response_type") != "code" {
		t.Fatalf("invalid authorization parameters: %v", query)
	}
	const expectedScopes = "account-settings.read workers-r2.read workers-r2-bucket-item.write account-api-tokens.write offline_access"
	if query.Get("scope") != expectedScopes || query.Has("client_secret") {
		t.Fatal("wrong public-client authorization")
	}
	if slices.Contains(RequiredScopes(), "offline_access") || !(TokenSet{Scope: "account-settings.read workers-r2.read workers-r2-bucket-item.write account-api-tokens.write"}).HasScopes(RequiredScopes()...) {
		t.Fatal("offline_access must be requested but not required")
	}
	state1, verifier1, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	state2, verifier2, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if state1 == verifier1 || state1 == state2 || verifier1 == verifier2 || !validVerifier(verifier1) {
		t.Fatal("PKCE secrets must be independent and unpredictable")
	}
	if _, err = base64.RawURLEncoding.DecodeString(state1); err != nil {
		t.Fatal(err)
	}
}

func TestTokenExchangeAndRotatingRefresh(t *testing.T) {
	var calls int
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/oauth2/token" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected token request: %s %s", r.Method, r.URL.Path)
		}
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "test-client" || r.Form.Has("client_secret") {
			t.Error("not a public-client exchange")
		}
		switch calls {
		case 1:
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != callback || r.Form.Get("code") != "one-use-code" || r.Form.Get("code_verifier") != verifier {
				t.Error("invalid code exchange")
			}
			jsonResponse(w, map[string]any{"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600, "token_type": "Bearer", "scope": "workers-r2-bucket-item.write account-api-tokens.write"})
		case 2:
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-1" || r.Form.Has("code") || r.Form.Has("code_verifier") {
				t.Error("invalid refresh grant")
			}
			jsonResponse(w, map[string]any{"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600})
		case 3:
			if r.Form.Get("refresh_token") != "refresh-2" {
				t.Error("did not use rotating refresh token")
			}
			jsonResponse(w, map[string]any{"access_token": "access-3", "expires_in": 60})
		}
	})
	before := time.Now()
	tokens, err := client.ExchangeCode(context.Background(), "one-use-code", callback, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "access-1" || tokens.RefreshToken != "refresh-1" || tokens.ExpiresAt.Before(before.Add(59*time.Minute)) || tokens.ExpiresAt.After(time.Now().Add(61*time.Minute)) {
		t.Fatal("incorrect token lifetime")
	}
	if !tokens.HasScopes("account-api-tokens.write") || tokens.HasScopes("workers-r2.write") {
		t.Fatal("incorrect granted scope handling")
	}
	tokens, err = client.Refresh(context.Background(), tokens)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken != "refresh-2" || !tokens.HasScopes("account-api-tokens.write") {
		t.Fatal("rotating refresh response was lost")
	}
	tokens, err = client.Refresh(context.Background(), tokens)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken != "refresh-2" {
		t.Fatal("omitted refresh token must preserve the current one")
	}
	if calls != 3 {
		t.Fatalf("got %d requests", calls)
	}
}

func TestAccountAndBucketPagination(t *testing.T) {
	var accountCalls, bucketCalls int
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Error("missing OAuth bearer")
		}
		switch r.URL.Path {
		case "/v4/accounts":
			accountCalls++
			if r.URL.Query().Get("page") != string(rune('0'+accountCalls)) {
				t.Error("account pages must advance")
			}
			apiResponse(w, []Account{{ID: accountID, Name: "Account"}}, map[string]int{"page": accountCalls, "total_pages": 2})
		case "/v4/accounts/" + accountID + "/r2/buckets":
			bucketCalls++
			if r.Header.Get("cf-r2-jurisdiction") != "eu" {
				t.Error("jurisdiction not retained")
			}
			if bucketCalls == 1 {
				apiResponse(w, map[string]any{"buckets": []Bucket{{Name: "app-one"}}}, map[string]string{"cursor": "next-page"})
			} else {
				if r.URL.Query().Get("cursor") != "next-page" {
					t.Error("bucket cursor not sent")
				}
				apiResponse(w, map[string]any{"buckets": []Bucket{{Name: "app-two", Jurisdiction: "eu"}}}, map[string]string{})
			}
		default:
			t.Errorf("unexpected URL: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	accounts, err := client.Accounts(context.Background(), "access-token")
	if err != nil || len(accounts) != 2 || accountCalls != 2 {
		t.Fatalf("accounts: %v %v", accounts, err)
	}
	buckets, err := client.Buckets(context.Background(), "access-token", accountID, "eu")
	if err != nil || bucketCalls != 2 || !reflect.DeepEqual(buckets, []Bucket{{Name: "app-one", Jurisdiction: "eu"}, {Name: "app-two", Jurisdiction: "eu"}}) {
		t.Fatalf("buckets: %v %v", buckets, err)
	}
}

func TestProvisionR2CredentialsRestrictsTheBucketAndDerivesS3Secret(t *testing.T) {
	expires := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	var created, deleted, revoked bool
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4/accounts/" + accountID + "/tokens/permission_groups":
			if r.URL.Query().Get("name") != "Workers R2 Storage Bucket Item Write" || r.URL.Query().Get("scope") != "com.cloudflare.edge.r2.bucket" || r.URL.Query().Has("page") {
				t.Error("permission lookup must use the endpoint's supported name/scope filters")
			}
			apiResponse(w, []map[string]any{{"id": permissionID, "name": "Workers R2 Storage Bucket Item Write", "is_selectable": true, "scopes": []string{"com.cloudflare.edge.r2.bucket"}}}, nil)
		case "/v4/accounts/" + accountID + "/tokens":
			created = true
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer access-token" {
				t.Error("unexpected provisioning request")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["expires_on"] != expires.Format(time.RFC3339) || body["name"] != "test device" {
				t.Error("expiry/name missing")
			}
			policies := body["policies"].([]any)
			if len(policies) != 1 {
				t.Fatal("too many policies")
			}
			policy := policies[0].(map[string]any)
			if policy["effect"] != "allow" || !reflect.DeepEqual(policy["resources"], map[string]any{"com.cloudflare.edge.r2.bucket." + accountID + "_eu_app-sync": "*"}) || !reflect.DeepEqual(policy["permission_groups"], []any{map[string]any{"id": permissionID}}) {
				t.Fatalf("excessive or incorrect policy: %#v", policy)
			}
			apiResponse(w, map[string]any{"id": tokenID, "value": "api-token-secret-value", "expires_on": expires.Format(time.RFC3339)}, nil)
		case "/v4/accounts/" + accountID + "/tokens/" + tokenID:
			deleted = true
			if r.Method != http.MethodDelete {
				t.Error("wrong deletion verb")
			}
			apiResponse(w, map[string]string{"id": tokenID}, nil)
		case "/oauth2/revoke":
			revoked = true
			_ = r.ParseForm()
			if r.Method != http.MethodPost || r.Form.Get("token") != "refresh-token" || r.Form.Get("client_id") != "test-client" {
				t.Error("wrong revocation request")
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	credentials, err := client.CreateCredentials(context.Background(), "access-token", accountID, "eu", "app-sync", "test device", expires)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("api-token-secret-value"))
	if !created || credentials.AccessKeyID != tokenID || credentials.TokenID != tokenID || credentials.SecretAccessKey != hex.EncodeToString(hash[:]) || !credentials.ExpiresAt.Equal(expires) {
		t.Fatalf("invalid S3 derivative: %#v", credentials)
	}
	encoded, _ := json.Marshal(credentials)
	if strings.Contains(string(encoded), "api-token-secret-value") {
		t.Fatal("raw API token must not leave provisioning")
	}
	if err = client.DeleteToken(context.Background(), "access-token", accountID, tokenID); err != nil {
		t.Fatal(err)
	}
	if err = client.Revoke(context.Background(), "refresh-token"); err != nil {
		t.Fatal(err)
	}
	if !deleted || !revoked {
		t.Fatal("remote credentials/authorization not revoked")
	}
}

func TestUnselectablePermissionDefersToAuthoritativeCreateEndpoint(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var writes atomic.Int32
			var events []DiagnosticEvent
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("CF-Ray", "0123456789abcdef-HKG")
				if r.Method == http.MethodGet {
					apiResponse(w, []map[string]any{{"id": permissionID, "name": "Workers R2 Storage Bucket Item Write", "is_selectable": false, "scopes": []string{"com.cloudflare.edge.r2.bucket"}}}, nil)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != "/v4/accounts/"+accountID+"/tokens" {
					t.Errorf("unexpected mutation: %s %s", r.Method, r.URL.Path)
				}
				writes.Add(1)
				var body struct {
					Policies []struct {
						Resources        map[string]string   `json:"resources"`
						PermissionGroups []map[string]string `json:"permission_groups"`
					} `json:"policies"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Policies) != 1 || !reflect.DeepEqual(body.Policies[0].Resources, map[string]string{"com.cloudflare.edge.r2.bucket." + accountID + "_default_app-sync": "*"}) || !reflect.DeepEqual(body.Policies[0].PermissionGroups, []map[string]string{{"id": permissionID}}) {
					t.Errorf("false catalog hint widened the bucket policy: %+v (%v)", body, err)
				}
				if status == http.StatusForbidden {
					w.WriteHeader(status)
					jsonResponse(w, map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "echoed-sensitive-token"}}})
					return
				}
				apiResponse(w, map[string]any{"id": tokenID, "value": "synthetic-created-secret"}, nil)
			})
			client.Diagnostic = func(event DiagnosticEvent) { events = append(events, event) }
			credentials, err := client.CreateCredentials(context.Background(), "access-token", accountID, "default", "app-sync", "app", time.Now().Add(time.Hour))
			if writes.Load() != 1 {
				t.Fatalf("catalog hint blocked the authoritative check (%d writes): %v", writes.Load(), err)
			}
			if status == http.StatusOK {
				if err != nil || credentials.AccessKeyID != tokenID {
					t.Fatalf("authoritative success was rejected: %v", err)
				}
			} else {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || !reflect.DeepEqual(apiErr.Codes, []int{10000}) || apiErr.CFRay != "0123456789abcdef-HKG" {
					t.Fatalf("authoritative denial detail lost: %v", err)
				}
				if !strings.Contains(err.Error(), "10000") || !strings.Contains(err.Error(), "0123456789abcdef-HKG") || strings.Contains(err.Error(), "echoed-sensitive-token") {
					t.Fatalf("unsafe or incomplete denial: %v", err)
				}
			}
			found := false
			for _, event := range events {
				if event.Phase == "permission_group" && event.PermissionSelectable != nil && !*event.PermissionSelectable && event.PermissionIDValid != nil && *event.PermissionIDValid && event.PermissionScopeValid != nil && *event.PermissionScopeValid {
					found = true
				}
			}
			if !found {
				t.Fatal("the false permission-catalog hint was not diagnosed")
			}
		})
	}
}

func TestMalformedPermissionGroupNeverCreatesCredentials(t *testing.T) {
	for _, test := range []struct {
		name, id string
		scopes   []string
	}{
		{"invalid ID", "not-an-id", []string{"com.cloudflare.edge.r2.bucket"}},
		{"missing resource scope", permissionID, nil},
		{"account-wide scope", permissionID, []string{"com.cloudflare.api.account"}},
		{"mixed scope", permissionID, []string{"com.cloudflare.edge.r2.bucket", "com.cloudflare.api.account"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				apiResponse(w, []map[string]any{{"id": test.id, "name": "Workers R2 Storage Bucket Item Write", "is_selectable": true, "scopes": test.scopes}}, nil)
			})
			_, err := client.CreateCredentials(context.Background(), "access", accountID, "default", "app-sync", "app", time.Now().Add(time.Hour))
			if err == nil || writes.Load() != 0 {
				t.Fatalf("unsafe permission group was accepted: %v", err)
			}
		})
	}
}

func TestBucketPaginationRejectsRepeatedCursor(t *testing.T) {
	var calls atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		apiResponse(w, map[string]any{"buckets": []Bucket{{Name: "app-sync"}}}, map[string]string{"cursor": "stuck"})
	})
	_, err := client.Buckets(context.Background(), "access", accountID, "default")
	if err == nil || calls.Load() != 2 {
		t.Fatalf("repeated cursor must stop without returning an incomplete list: %v (%d calls)", err, calls.Load())
	}
}

func TestAPILogicalFailureCannotBeTreatedAsSuccess(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]any{"success": false, "result": []Account{{ID: accountID}}, "errors": []map[string]any{{"code": 10000, "message": "echoed-access-secret"}}})
	})
	accounts, err := client.Accounts(context.Background(), "access")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || len(accounts) != 0 || !reflect.DeepEqual(apiErr.Codes, []int{10000}) || strings.Contains(err.Error(), "echoed-access-secret") {
		t.Fatalf("logical API failure was lost or exposed secrets: %v %v", accounts, err)
	}
}

func TestFailedResponsesNeverExposeSecrets(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				jsonResponse(w, map[string]any{"error": "invalid_grant", "error_description": "refresh-secret authorization-code", "errors": []map[string]any{{"code": 10000, "message": "access-secret"}}})
			})
			_, err := client.Refresh(context.Background(), TokenSet{RefreshToken: "refresh-secret"})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status || apiErr.OAuthError != "invalid_grant" {
				t.Fatalf("missing structured status: %v", err)
			}
			for _, secret := range []string{"refresh-secret", "authorization-code", "access-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("secret leaked in error")
				}
			}
		})
	}
}

func TestRedirectCannotForwardOAuthSecrets(t *testing.T) {
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer destination.Close()
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	})
	_, err := client.Refresh(context.Background(), TokenSet{RefreshToken: "refresh-secret"})
	if err == nil || reached.Load() {
		t.Fatal("OAuth redirect forwarded secret form")
	}
}

func TestDeleteTokenRetriesOnlyExplicitNotFoundAsSuccess(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			jsonResponse(w, map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "synthetic"}}})
		})
		err := client.DeleteToken(context.Background(), "access", accountID, tokenID)
		if (status == http.StatusNotFound && err != nil) || (status == http.StatusForbidden && err == nil) {
			t.Fatalf("incorrect cleanup outcome for HTTP %d: %v", status, err)
		}
	}
}

func TestCancellationAndOversizedResponse(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		started := make(chan struct{})
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() })
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := client.Accounts(ctx, "access"); done <- err }()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("context cancellation lost: %v", err)
		}
	})
	t.Run("request timeout", func(t *testing.T) {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		client.RequestTimeout = 20 * time.Millisecond
		started := time.Now()
		if _, err := client.Accounts(context.Background(), "access"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("RequestTimeout was not applied: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("request ran for %v despite a 20ms RequestTimeout", elapsed)
		}
	})
	t.Run("size", func(t *testing.T) {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
		})
		if _, err := client.Accounts(context.Background(), "access"); err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("oversized response accepted: %v", err)
		}
	})
}

func TestRejectsUnsafeInputsBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) })
	for _, redirect := range []string{"http://evil.example/callback", "https://user:secret@example.com/callback", "https://example.com/callback?code=secret", "javascript:alert(1)", "app://callback"} {
		if _, err := client.AuthorizationURL(redirect, "state", verifier); err == nil {
			t.Fatalf("unsafe redirect accepted: %s", redirect)
		}
	}
	for _, account := range []string{"../user", "", strings.Repeat("f", 31), strings.Repeat("x", 32)} {
		if _, err := client.Buckets(context.Background(), "access", account, "default"); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
	if _, err := client.CreateCredentials(context.Background(), "access", accountID, "eu", "bucket/../other", "name", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("invalid bucket accepted")
	}
	if _, err := client.CreateCredentials(context.Background(), "access", accountID, "eu", "app", "name", time.Time{}); err == nil {
		t.Fatal("unbounded credential lifetime accepted")
	}
	if requests.Load() != 0 {
		t.Fatal("invalid configuration reached network")
	}
	client.APIBaseURL = "http://api.cloudflare.com/client/v4"
	if _, err := client.Accounts(context.Background(), "access"); err == nil {
		t.Fatal("unencrypted remote API accepted")
	}
}

func TestR2EndpointsMatchManualConfiguration(t *testing.T) {
	for jurisdiction, expected := range map[string]string{"": "", "default": "", "eu": ".eu", "us": ".us", "fedramp": ".fedramp"} {
		endpoint, err := Endpoint(accountID, jurisdiction)
		if err != nil || endpoint != "https://"+accountID+expected+".r2.cloudflarestorage.com" {
			t.Fatalf("wrong endpoint for %q: %q %v", jurisdiction, endpoint, err)
		}
	}
}
