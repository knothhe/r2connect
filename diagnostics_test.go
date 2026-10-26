package r2connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticEventsContainOnlyOperationalAllowlist(t *testing.T) {
	const access = "synthetic-sensitive-access-token"
	const refresh = "synthetic-sensitive-refresh-token"
	const authorizationCode = "synthetic-sensitive-authorization-code"
	const accountName = "sensitive-account-name"
	const bucketName = "sensitive-bucket-name"
	const responseMessage = "sensitive-upstream-error-description"
	var events []DiagnosticEvent
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "fedcba9876543210-HKG")
		switch {
		case r.URL.Path == "/oauth2/token":
			jsonResponse(w, map[string]any{"access_token": access, "refresh_token": refresh, "expires_in": 3600, "scope": OAuthScopes})
		case r.URL.Path == "/v4/accounts":
			apiResponse(w, []Account{{ID: accountID, Name: accountName}}, nil)
		case strings.HasSuffix(r.URL.Path, "/r2/buckets"):
			apiResponse(w, map[string]any{"buckets": []Bucket{{Name: bucketName}}}, nil)
		case strings.HasSuffix(r.URL.Path, "/tokens/permission_groups"):
			apiResponse(w, []map[string]any{{"id": permissionID, "name": "Workers R2 Storage Bucket Item Write", "is_selectable": false, "scopes": []string{"com.cloudflare.edge.r2.bucket"}}}, nil)
		case strings.HasSuffix(r.URL.Path, "/tokens"):
			w.WriteHeader(http.StatusForbidden)
			jsonResponse(w, map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": responseMessage + " " + access + " " + refresh + " " + authorizationCode + " " + verifier}}})
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	})
	client.Diagnostic = func(event DiagnosticEvent) { events = append(events, event) }
	tokens, err := client.ExchangeCode(context.Background(), authorizationCode, callback, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Accounts(context.Background(), tokens.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Buckets(context.Background(), tokens.AccessToken, accountID, "default"); err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateCredentials(context.Background(), tokens.AccessToken, accountID, "default", bucketName, "sensitive-credential-name", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("fixture must return an authoritative denial")
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{access, refresh, authorizationCode, verifier, callback, accountName, accountID, bucketName, permissionID, "sensitive-credential-name", responseMessage, "Authorization", "Bearer", "http://", "client_id", "code_verifier"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("diagnostic events exposed %q: %s", sensitive, encoded)
		}
	}
	started, completed, denied, catalog := false, false, false, false
	for _, event := range events {
		if event.Operation == "create R2 credentials" && event.Phase == "request_started" && event.Method == "POST" {
			started = true
		}
		if event.Operation == "create R2 credentials" && event.Phase == "request_completed" && event.Method == "POST" && event.HTTPStatus == 403 && event.CFRay == "fedcba9876543210-HKG" && reflect.DeepEqual(event.ErrorCodes, []int{9109}) && event.Result == "http_error" {
			denied = true
		}
		if event.Operation == "exchange Cloudflare authorization" && event.Phase == "request_completed" && event.HTTPStatus == 200 && event.Result == "success" {
			completed = true
		}
		if event.Phase == "permission_group" && event.PermissionSelectable != nil && !*event.PermissionSelectable {
			catalog = true
		}
	}
	if !started || !completed || !denied || !catalog {
		t.Fatalf("missing safe diagnostic evidence: %s", encoded)
	}
}

func TestDiagnosticLogicalFailureRetainsCodesAndSafeRay(t *testing.T) {
	var events []DiagnosticEvent
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "0123456789abcdef-SJC")
		jsonResponse(w, map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "sensitive-message"}}})
	})
	client.Diagnostic = func(event DiagnosticEvent) { events = append(events, event) }
	_, err := client.Accounts(context.Background(), "sensitive-access")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 200 || apiErr.CFRay != "0123456789abcdef-SJC" || !reflect.DeepEqual(apiErr.Codes, []int{10000}) {
		t.Fatalf("logical failure lost actionable information: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Phase == "api_result" && event.Result == "api_error" && event.HTTPStatus == 200 && event.CFRay == apiErr.CFRay && reflect.DeepEqual(event.ErrorCodes, apiErr.Codes) {
			found = true
		}
	}
	if !found {
		t.Fatalf("HTTP 200 logical failure was not recorded: %+v", events)
	}
}

func TestDiagnosticRejectsUnknownFreeTextAndHeaderValues(t *testing.T) {
	var events []DiagnosticEvent
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Ray", "synthetic-sensitive-header")
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, map[string]any{"errors": []map[string]any{{"code": 9109, "message": "synthetic-sensitive-message"}}})
	})
	client.Diagnostic = func(event DiagnosticEvent) { events = append(events, event) }
	u, _ := url.Parse(client.APIBaseURL + "/accounts?private=sensitive-query")
	err := client.request(context.Background(), "synthetic-sensitive-operation", http.MethodGet, u, "synthetic-sensitive-token", "application/json", nil, nil, nil)
	if err == nil {
		t.Fatal("fixture must fail")
	}
	encoded, _ := json.Marshal(events)
	for _, value := range []string{"synthetic-sensitive", "sensitive-query", "private="} {
		if strings.Contains(string(encoded), value) {
			t.Fatalf("free text entered operational diagnostic: %s", encoded)
		}
	}
	for _, event := range events {
		if event.Operation != "Cloudflare request" || event.CFRay != "" {
			t.Fatalf("untrusted field was retained: %+v", event)
		}
	}
	if strings.Contains(err.Error(), "synthetic-sensitive-header") || strings.Contains(err.Error(), "synthetic-sensitive-message") {
		t.Fatal("upstream free text entered returned error")
	}
	before := len(events)
	client.diagnose(DiagnosticEvent{Operation: "create R2 credentials", Phase: "arbitrary-sensitive-phase", Result: "success"})
	client.diagnose(DiagnosticEvent{Operation: "create R2 credentials", Phase: "request_completed", Result: "arbitrary-sensitive-result"})
	if len(events) != before {
		t.Fatal("untrusted phase/result entered diagnostic")
	}
}

func TestDiagnosticCancellationIsObservableWithoutTransportErrorText(t *testing.T) {
	var events []DiagnosticEvent
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {})
	client.Diagnostic = func(event DiagnosticEvent) { events = append(events, event) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Accounts(ctx, "sensitive-access")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was lost: %v", err)
	}
	if len(events) != 2 || events[1].Phase != "request_completed" || events[1].Result != "canceled" || events[1].HTTPStatus != 0 {
		t.Fatalf("cancellation not classified: %+v", events)
	}
}
