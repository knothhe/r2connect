package loopback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/knothhe/r2connect"
)

type oauthFixture struct {
	mu              sync.Mutex
	exchanges       int
	revoked         []string
	exchangeStarted chan struct{}
	exchangeRelease chan struct{}
}

func (f *oauthFixture) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	switch req.URL.Path {
	case "/oauth2/token":
		f.mu.Lock()
		f.exchanges++
		started, release := f.exchangeStarted, f.exchangeRelease
		f.mu.Unlock()
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		if release != nil {
			select {
			case <-release:
			case <-req.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 3600, "token_type": "Bearer", "scope": r2connect.OAuthScopes})
	case "/oauth2/revoke":
		f.mu.Lock()
		f.revoked = append(f.revoked, req.Form.Get("token"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected request", 404)
	}
}

func (f *oauthFixture) counts() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges, append([]string{}, f.revoked...)
}

func freePort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	return port
}

func testFlow(t *testing.T, opts Options) (*Flow, *oauthFixture) {
	t.Helper()
	fixture := &oauthFixture{}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	client := r2connect.NewClient("synthetic-client")
	client.OAuthBaseURL, client.APIBaseURL = server.URL+"/oauth2", server.URL+"/client/v4"
	opts.RedirectURI = fmt.Sprintf("http://localhost:%d/callback", freePort(t))
	f, err := Start(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	return f, fixture
}

func callback(t *testing.T, f *Flow, query url.Values) int {
	t.Helper()
	u := *f.redirect
	u.RawQuery = query.Encode()
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func authState(t *testing.T, f *Flow) string {
	t.Helper()
	u, err := url.Parse(f.URL())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("client_secret") != "" {
		t.Fatal("authorization did not use PKCE without a client secret")
	}
	return q.Get("state")
}

type waitResult struct {
	tokens r2connect.TokenSet
	err    error
}

func wait(ctx context.Context, f *Flow) <-chan waitResult {
	done := make(chan waitResult, 1)
	go func() {
		tokens, err := f.Wait(ctx)
		done <- waitResult{tokens, err}
	}()
	return done
}

func receive(t *testing.T, done <-chan waitResult) waitResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(4 * time.Second):
		t.Fatal("flow did not finish")
	}
	return waitResult{}
}

func TestParseRedirectRejectsOffDeviceOrAmbiguousCallbacks(t *testing.T) {
	for _, value := range []string{
		"https://localhost:18796/callback", "http://example.com:18796/callback", "http://127.0.0.1.example.com:18796/callback",
		"http://localhost/callback", "http://localhost:0/callback", "http://localhost:65536/callback", "http://localhost:18796",
		"http://user@localhost:18796/callback", "http://localhost:18796/callback?code=other", "http://localhost:18796/callback?",
		"http://localhost:18796/callback#fragment", "http://localhost:18796/%63allback",
	} {
		if _, err := ParseRedirect(value); !errors.Is(err, ErrRedirect) {
			t.Fatalf("accepted off-device or ambiguous callback %q: %v", value, err)
		}
	}
	for _, value := range []string{"http://localhost:18796/oauth/cloudflare/callback", "http://127.0.0.1:18796/callback", "http://[::1]:18796/callback"} {
		u, err := ParseRedirect(value)
		if err != nil {
			t.Fatalf("valid loopback callback rejected: %s: %v", value, err)
		}
		addresses := listenAddresses(u)
		if len(addresses) == 0 || addresses[0].optional {
			t.Fatal("loopback callback did not produce a required local listener")
		}
		for _, candidate := range addresses {
			if host, _, err := net.SplitHostPort(candidate.address); err != nil || !net.ParseIP(host).IsLoopback() {
				t.Fatalf("callback listener is not loopback: %s", candidate.address)
			}
		}
	}
}

func TestLocalhostCallbackAcceptsBothLoopbackFamilies(t *testing.T) {
	port := freePort(t)
	u, err := ParseRedirect(fmt.Sprintf("http://localhost:%d/callback", port))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(u)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })}
	go server.Serve(listener)
	defer server.Close()
	hosts := []string{"127.0.0.1"}
	if ipv6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		_ = ipv6.Close()
		hosts = append(hosts, "::1")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	for _, host := range hosts {
		response, err := client.Get("http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/")
		if err != nil {
			t.Fatalf("callback was not reachable over %s: %v", host, err)
		}
		_ = response.Body.Close()
	}
	_ = listener.Close()
	if _, err = listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed callback listener kept accepting")
	}
}

func TestStartReportsBusyPort(t *testing.T) {
	first, _ := testFlow(t, Options{})
	defer first.Close()
	_, err := Start(first.client, Options{RedirectURI: first.opts.RedirectURI})
	if !errors.Is(err, ErrListen) {
		t.Fatalf("busy callback port was not reported: %v", err)
	}
}

func TestFlowAcceptsTokensBeforeAnsweringBrowser(t *testing.T) {
	var accepted r2connect.TokenSet
	var doneCalls int
	var doneErr error
	f, fixture := testFlow(t, Options{
		Accept: func(_ context.Context, tokens r2connect.TokenSet) error { accepted = tokens; return nil },
		Done:   func(err error) { doneCalls++; doneErr = err },
	})
	done := wait(t.Context(), f)
	if code := callback(t, f, url.Values{"state": {authState(t, f)}, "code": {"synthetic-code"}}); code != 200 {
		t.Fatalf("valid callback returned HTTP %d", code)
	}
	// Done runs before the page is written, so callers can publish status first.
	if doneCalls != 1 || doneErr != nil || accepted.AccessToken != "synthetic-access" {
		t.Fatal("result was not delivered before the browser was answered")
	}
	result := receive(t, done)
	if result.err != nil || result.tokens.RefreshToken != "synthetic-refresh" {
		t.Fatalf("flow result: %+v", result)
	}
	if exchanges, revoked := fixture.counts(); exchanges != 1 || len(revoked) != 0 {
		t.Fatal("successful flow exchanged more than once or revoked its grant")
	}
}

func TestFlowRejectsWrongOrDuplicateState(t *testing.T) {
	f, fixture := testFlow(t, Options{})
	ctx, cancel := context.WithCancel(t.Context())
	done := wait(ctx, f)
	state := authState(t, f)
	if code := callback(t, f, url.Values{"state": {"wrong-state"}, "code": {"must-not-exchange"}}); code != 400 {
		t.Fatal("wrong state was accepted")
	}
	if code := callback(t, f, url.Values{"state": {state, state}, "code": {"must-not-exchange"}}); code != 400 {
		t.Fatal("duplicate state parameters were accepted")
	}
	if code := callback(t, f, url.Values{"state": {state}}); code != 400 {
		t.Fatal("a callback without a code was accepted")
	}
	cancel()
	if result := receive(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled flow returned %v", result.err)
	}
	if exchanges, _ := fixture.counts(); exchanges != 0 {
		t.Fatal("invalid or canceled authorization exchanged a code")
	}
}

func TestFlowTimeoutIsDistinctFromCancellation(t *testing.T) {
	var events []Event
	var mu sync.Mutex
	f, _ := testFlow(t, Options{Diagnostic: func(event Event) { mu.Lock(); events = append(events, event); mu.Unlock() }})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if result := receive(t, wait(ctx, f)); !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("expired flow returned %v", result.err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0].Stage != "context_done" || events[0].Result != "timeout" || events[1].Stage != "listener_closed" {
		t.Fatalf("unexpected timeout events: %+v", events)
	}
}

func TestFlowReportsOAuthErrors(t *testing.T) {
	for _, test := range []struct {
		code string
		want error
	}{{"access_denied", ErrDenied}, {"invalid_scope", ErrInvalidScope}, {"server_error", nil}, {"secret\nvalue", nil}} {
		t.Run(test.code, func(t *testing.T) {
			f, fixture := testFlow(t, Options{})
			done := wait(t.Context(), f)
			if code := callback(t, f, url.Values{"state": {authState(t, f)}, "error": {test.code}, "error_description": {"synthetic secret description"}}); code != 200 {
				t.Fatalf("OAuth error page returned HTTP %d", code)
			}
			result := receive(t, done)
			var oauthErr *OAuthError
			if !errors.As(result.err, &oauthErr) || oauthErr.Code != ErrorCode(test.code) {
				t.Fatalf("OAuth error was not reported: %v", result.err)
			}
			if test.want != nil && !errors.Is(result.err, test.want) || test.want == nil && (errors.Is(result.err, ErrDenied) || errors.Is(result.err, ErrInvalidScope)) {
				t.Fatalf("OAuth error matched the wrong sentinel: %v", result.err)
			}
			if exchanges, _ := fixture.counts(); exchanges != 0 {
				t.Fatal("an OAuth error exchanged a code")
			}
		})
	}
}

func TestFlowRevokesGrantWhenAcceptFails(t *testing.T) {
	failure := errors.New("synthetic save failure")
	f, fixture := testFlow(t, Options{Accept: func(context.Context, r2connect.TokenSet) error { return failure }})
	done := wait(t.Context(), f)
	if code := callback(t, f, url.Values{"state": {authState(t, f)}, "code": {"synthetic-code"}}); code != 400 {
		t.Fatalf("failed save returned HTTP %d", code)
	}
	if result := receive(t, done); !errors.Is(result.err, failure) || result.tokens.AccessToken != "" {
		t.Fatalf("failed save was not reported: %+v", result)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, revoked := fixture.counts(); len(revoked) == 1 && revoked[0] == "synthetic-refresh" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a rejected grant was not revoked")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDuplicateCallbackExchangesCodeOnce(t *testing.T) {
	f, fixture := testFlow(t, Options{})
	fixture.exchangeStarted, fixture.exchangeRelease = make(chan struct{}, 1), make(chan struct{})
	done := wait(t.Context(), f)
	state := authState(t, f)
	codes := make(chan int, 2)
	call := func() { codes <- callback(t, f, url.Values{"state": {state}, "code": {"single-use-code"}}) }
	go call()
	select {
	case <-fixture.exchangeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not begin")
	}
	go call()
	// The duplicate is rejected while the first exchange is still running.
	select {
	case code := <-codes:
		if code != 409 {
			t.Fatalf("duplicate callback returned HTTP %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplicate callback waited for the first exchange")
	}
	close(fixture.exchangeRelease)
	if code := <-codes; code != 200 {
		t.Fatalf("original callback returned HTTP %d", code)
	}
	if result := receive(t, done); result.err != nil {
		t.Fatal(result.err)
	}
	if exchanges, _ := fixture.counts(); exchanges != 1 {
		t.Fatal("a duplicate callback exchanged a single-use code more than once")
	}
}

func TestCancellationDuringExchangeDiscardsLateGrant(t *testing.T) {
	accepted := false
	f, fixture := testFlow(t, Options{Accept: func(ctx context.Context, _ r2connect.TokenSet) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		accepted = true
		return nil
	}})
	fixture.exchangeStarted, fixture.exchangeRelease = make(chan struct{}, 1), make(chan struct{})
	defer close(fixture.exchangeRelease)
	ctx, cancel := context.WithCancel(t.Context())
	done := wait(ctx, f)
	codes := make(chan int, 1)
	go func() { codes <- callback(t, f, url.Values{"state": {authState(t, f)}, "code": {"slow-code"}}) }()
	select {
	case <-fixture.exchangeStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not begin")
	}
	cancel()
	if result := receive(t, done); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled exchange returned %v", result.err)
	}
	select {
	case <-codes:
	case <-time.After(4 * time.Second):
		t.Fatal("canceled callback did not finish")
	}
	if accepted {
		t.Fatal("a late token response was accepted after cancellation")
	}
}

func TestCloseStopsPendingFlow(t *testing.T) {
	f, _ := testFlow(t, Options{})
	done := wait(t.Context(), f)
	time.Sleep(20 * time.Millisecond)
	_ = f.Close()
	if result := receive(t, done); !errors.Is(result.err, ErrCallbackStopped) {
		t.Fatalf("closed listener returned %v", result.err)
	}
}

func TestErrorCodeKeepsOnlyStandardCodes(t *testing.T) {
	for value, want := range map[string]string{"": "", "invalid_scope": "invalid_scope", "access_denied": "access_denied", "invalid_scope extra": "other", "secret\nvalue": "other"} {
		if got := ErrorCode(value); got != want {
			t.Fatalf("ErrorCode(%q) = %q, want %q", value, got, want)
		}
	}
}
