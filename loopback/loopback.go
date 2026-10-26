// Package loopback runs the native OAuth authorization-code flow for r2connect:
// PKCE, a one-shot loopback callback listener and the code exchange. The
// application never needs a client secret.
package loopback

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knothhe/r2connect"
)

var (
	// ErrListen reports that the callback port could not be opened, usually
	// because another sign-in is still listening on it.
	ErrListen = errors.New("the OAuth callback port is in use")
	// ErrDenied matches an *OAuthError for access_denied. Cloudflare reports
	// both Cancel and an incomplete grant this way; its consent page leaves the
	// sensitive API token scope off by default.
	ErrDenied = errors.New("Cloudflare authorization was denied")
	// ErrInvalidScope matches an *OAuthError for invalid_scope: the OAuth client
	// is not allowed to request the scopes r2connect needs.
	ErrInvalidScope = errors.New("Cloudflare rejected the requested permissions (invalid_scope)")
	// ErrCallbackStopped reports that the callback listener stopped before the
	// flow finished, without the context being canceled.
	ErrCallbackStopped = errors.New("the OAuth callback listener stopped")
)

// OAuthError is an error the authorization server returned to the callback.
// Code is one of the standard OAuth error codes, or "other".
type OAuthError struct{ Code string }

func (e *OAuthError) Error() string { return "Cloudflare sign-in was not authorized (" + e.Code + ")" }

func (e *OAuthError) Is(target error) bool {
	return target == ErrDenied && e.Code == "access_denied" || target == ErrInvalidScope && e.Code == "invalid_scope"
}

// ErrorCode keeps only the standard OAuth error codes; any other callback value
// is reported as "other" so arbitrary text never reaches logs or errors.
func ErrorCode(value string) string {
	switch value {
	case "":
		return ""
	case "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope", "server_error", "temporarily_unavailable", "invalid_state":
		return value
	}
	return "other"
}

// Event is a diagnostic record. Only explicit stage names, results and
// booleans cross this boundary; never an error, URL, query or response body.
type Event struct {
	Stage             string
	Result            string
	MethodMatches     *bool
	HostMatches       *bool
	PathMatches       *bool
	StatePresent      *bool
	StateMatches      *bool
	CodePresent       *bool
	OAuthErrorPresent *bool
	OAuthError        string
}

// Messages are the plain-text pages the browser shows after the callback.
type Messages struct {
	Connected     string
	Denied        string
	InvalidScope  string
	NotAuthorized string
	Canceled      string
	Failed        string
}

var defaultMessages = Messages{
	Connected:     "Cloudflare is connected. You can close this page and return to the application.",
	Denied:        "Cloudflare sign-in was denied. Return to the application to retry, and turn on Account API Tokens Write under Edit Permissions before you authorize.",
	InvalidScope:  "Cloudflare rejected the requested permissions. Return to the application for details.",
	NotAuthorized: "Cloudflare sign-in was not authorized. Return to the application to retry.",
	Canceled:      "Cloudflare sign-in was canceled. Return to the application to retry.",
	Failed:        "Cloudflare sign-in could not be saved. Return to the application for details.",
}

type Options struct {
	// RedirectURI must satisfy ParseRedirect and be registered for the client.
	RedirectURI string
	// Accept runs after the code exchange and before the browser is answered,
	// typically Manager.Authorize. When it fails, the new grant is revoked.
	Accept func(context.Context, r2connect.TokenSet) error
	// Done receives the flow's result exactly once, before the browser page is
	// written: nil, an *OAuthError, the context's error, ErrCallbackStopped, or
	// the exchange or Accept error.
	Done       func(error)
	Diagnostic func(Event)
	// Messages overrides the browser pages; empty fields keep the defaults.
	Messages Messages
}

// Flow is one pending authorization. Start it, send the user to URL, then
// Wait. Close stops the callback listener early.
type Flow struct {
	client   *r2connect.Client
	opts     Options
	redirect *url.URL
	listener net.Listener
	state    string
	verifier string
	url      string
	waited   atomic.Bool

	mu       sync.Mutex
	consumed bool // One code exchange per authorization.
	tokens   r2connect.TokenSet
}

// Start prepares PKCE and opens the callback listener, so a busy port is
// reported before the browser opens.
func Start(client *r2connect.Client, opts Options) (*Flow, error) {
	u, err := ParseRedirect(opts.RedirectURI)
	if err != nil {
		return nil, err
	}
	state, verifier, err := r2connect.NewPKCE()
	if err != nil {
		return nil, err
	}
	authURL, err := client.AuthorizationURL(opts.RedirectURI, state, verifier)
	if err != nil {
		return nil, err
	}
	listener, err := Listen(u)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrListen, err)
	}
	m, d := &opts.Messages, defaultMessages
	for _, field := range [][2]*string{{&m.Connected, &d.Connected}, {&m.Denied, &d.Denied}, {&m.InvalidScope, &d.InvalidScope}, {&m.NotAuthorized, &d.NotAuthorized}, {&m.Canceled, &d.Canceled}, {&m.Failed, &d.Failed}} {
		if *field[0] == "" {
			*field[0] = *field[1]
		}
	}
	return &Flow{client: client, opts: opts, redirect: u, listener: listener, state: state, verifier: verifier, url: authURL}, nil
}

// URL is the authorization page to open in the user's browser.
func (f *Flow) URL() string { return f.url }

// Close stops the callback listener. A pending Wait returns ErrCallbackStopped
// unless its context has already ended.
func (f *Flow) Close() error { return f.listener.Close() }

// Authorize starts a flow, opens its URL and waits for the result.
func Authorize(ctx context.Context, client *r2connect.Client, opts Options, open func(string) error) (r2connect.TokenSet, error) {
	f, err := Start(client, opts)
	if err != nil {
		return r2connect.TokenSet{}, err
	}
	if err = open(f.URL()); err != nil {
		_ = f.Close()
		return r2connect.TokenSet{}, err
	}
	return f.Wait(ctx)
}

func (f *Flow) diagnose(event Event) {
	if f.opts.Diagnostic != nil {
		f.opts.Diagnostic(event)
	}
}

func flag(value bool) *bool { return &value }

// Wait serves the callback until the flow finishes or ctx ends, then closes
// the listener. It may be called once.
func (f *Flow) Wait(ctx context.Context) (r2connect.TokenSet, error) {
	if f.waited.Swap(true) {
		return r2connect.TokenSet{}, errors.New("the OAuth flow is already being waited on")
	}
	var once sync.Once
	var result error
	finished := make(chan struct{})
	finish := func(err error) {
		once.Do(func() {
			result = err
			if f.opts.Done != nil {
				f.opts.Done(err)
			}
			close(finished)
		})
	}
	defer func() {
		_ = f.listener.Close()
		f.diagnose(Event{Stage: "listener_closed"})
	}()
	host, path := f.redirect.Host, f.redirect.Path
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		q := req.URL.Query()
		stateMatches := len(q["state"]) == 1 && subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.state)) == 1
		if req.Method != "GET" || req.Host != host || req.URL.Path != path {
			f.diagnose(Event{Stage: "callback_rejected", Result: "invalid_request"})
			http.Error(w, "Invalid callback.", 400)
			return
		}
		if !stateMatches {
			f.diagnose(Event{Stage: "callback_rejected", Result: "invalid_state"})
			http.Error(w, "Invalid authorization state.", 400)
			return
		}
		f.mu.Lock()
		if f.consumed || ctx.Err() != nil {
			f.mu.Unlock()
			f.diagnose(Event{Stage: "callback_rejected", Result: "inactive"})
			http.Error(w, "Sign-in is no longer active.", 409)
			return
		}
		if q.Get("error") != "" {
			f.consumed = true
			f.mu.Unlock()
			err := &OAuthError{Code: ErrorCode(q.Get("error"))}
			finish(err)
			switch {
			case errors.Is(err, ErrDenied):
				io.WriteString(w, f.opts.Messages.Denied)
			case errors.Is(err, ErrInvalidScope):
				io.WriteString(w, f.opts.Messages.InvalidScope)
			default:
				io.WriteString(w, f.opts.Messages.NotAuthorized)
			}
			return
		}
		if len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 8192 {
			f.mu.Unlock()
			f.diagnose(Event{Stage: "callback_rejected", Result: "invalid_code"})
			http.Error(w, "Missing authorization code.", 400)
			return
		}
		f.consumed = true
		f.mu.Unlock()
		// Network and Accept I/O leave cancellation available; Accept checks the
		// context again before it commits anything.
		f.diagnose(Event{Stage: "code_exchange_started"})
		tokens, err := f.client.ExchangeCode(ctx, q.Get("code"), f.opts.RedirectURI, f.verifier)
		exchangeResult := "success"
		if err != nil {
			exchangeResult = "failed"
		}
		f.diagnose(Event{Stage: "code_exchange_finished", Result: exchangeResult})
		if err == nil && f.opts.Accept != nil {
			err = f.opts.Accept(ctx, tokens)
		}
		if err != nil {
			discard(f.client, tokens)
			if ctx.Err() != nil {
				finish(ctx.Err())
				http.Error(w, f.opts.Messages.Canceled, 409)
				return
			}
			finish(err)
			http.Error(w, f.opts.Messages.Failed, 400)
			return
		}
		f.mu.Lock()
		f.tokens = tokens
		f.mu.Unlock()
		finish(nil)
		io.WriteString(w, f.opts.Messages.Connected)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		stateMatches := len(q["state"]) == 1 && subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.state)) == 1
		f.diagnose(Event{Stage: "callback_received",
			MethodMatches: flag(req.Method == "GET"), HostMatches: flag(req.Host == host), PathMatches: flag(req.URL.Path == path),
			StatePresent: flag(len(q["state"]) > 0), StateMatches: flag(stateMatches),
			CodePresent: flag(q.Get("code") != ""), OAuthErrorPresent: flag(q.Get("error") != ""), OAuthError: ErrorCode(q.Get("error"))})
		mux.ServeHTTP(w, req)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, MaxHeaderBytes: 16 << 10}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := server.Serve(f.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			if ctx.Err() != nil {
				return // Cancellation usually closes the listener as well.
			}
			f.diagnose(Event{Stage: "listener_error"})
			finish(ErrCallbackStopped)
		}
	}()
	select {
	case <-ctx.Done():
		eventResult := "canceled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			eventResult = "timeout"
		}
		f.diagnose(Event{Stage: "context_done", Result: eventResult})
		finish(ctx.Err())
	case <-finished:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	_ = server.Close()
	<-serverDone
	if result != nil {
		return r2connect.TokenSet{}, result
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens, nil
}

// discard revokes a grant the application will not keep. It runs in the
// background so the browser is answered promptly.
func discard(client *r2connect.Client, tokens r2connect.TokenSet) {
	token := tokens.RefreshToken
	if token == "" {
		token = tokens.AccessToken
	}
	if token == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = client.Revoke(ctx, token)
	}()
}
