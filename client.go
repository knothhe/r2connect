// Package r2connect connects an application to a user's Cloudflare R2 bucket
// through OAuth. Client implements the account control plane used to provision
// private, bucket-scoped R2 credentials; Manager keeps those credentials renewed
// and cleans them up. Object data continues to use the S3 API.
package r2connect

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPIBaseURL   = "https://api.cloudflare.com/client/v4"
	DefaultOAuthBaseURL = "https://dash.cloudflare.com/oauth2"
	// Scope names come from GET /oauth/scopes, rather than Wrangler's older
	// colon-delimited, internal-client scope names.
	requiredScopes = "account-settings.read workers-r2.read workers-r2-bucket-item.write account-api-tokens.write"
	// offline_access asks for a refresh token so R2 credentials can be renewed
	// without a browser. It is not required: a code-only grant still works.
	OAuthScopes      = requiredScopes + " offline_access"
	maxResponseBytes = 2 << 20
	maxPages         = 100
)

// RequiredScopes returns a fresh copy of the permissions needed to enumerate
// accounts/buckets and provision object credentials. offline_access is
// requested but optional, so it is not part of this set.
func RequiredScopes() []string {
	return strings.Fields(requiredScopes)
}

type TokenSet struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func (t TokenSet) HasScopes(required ...string) bool {
	granted := make(map[string]bool)
	for _, scope := range strings.Fields(t.Scope) {
		granted[scope] = true
	}
	for _, scope := range required {
		if !granted[scope] {
			return false
		}
	}
	return true
}

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Bucket struct {
	Name         string `json:"name"`
	Jurisdiction string `json:"jurisdiction"`
}

// Credentials contains only the S3 derivative, never the API token value.
type Credentials struct {
	TokenID         string    `json:"tokenId"`
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// Client defaults to Cloudflare's public endpoints. Endpoint overrides support
// isolated tests; they may use HTTP only on a loopback address. Callers must not
// populate them from untrusted user input.
type Client struct {
	ClientID     string
	HTTPClient   *http.Client
	APIBaseURL   string
	OAuthBaseURL string
	Diagnostic   func(DiagnosticEvent)
}

func NewClient(clientID string) *Client {
	return &Client{ClientID: clientID, HTTPClient: &http.Client{Timeout: 30 * time.Second}, APIBaseURL: DefaultAPIBaseURL, OAuthBaseURL: DefaultOAuthBaseURL}
}

// NewPKCE generates independent CSRF state and an RFC 7636 verifier. The
// verifier stays in the native backend until the code has been exchanged.
func NewPKCE() (state, verifier string, err error) {
	var data [64]byte
	if _, err = rand.Read(data[:]); err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:32]), base64.RawURLEncoding.EncodeToString(data[32:]), nil
}

func (c *Client) AuthorizationURL(redirectURI, state, verifier string) (string, error) {
	if err := c.validateClient(); err != nil {
		return "", err
	}
	if err := validateRedirect(redirectURI); err != nil {
		return "", err
	}
	if state == "" || len(state) > 1024 || !validVerifier(verifier) {
		return "", errors.New("invalid OAuth state or PKCE verifier")
	}
	u, err := endpoint(c.OAuthBaseURL, "/auth")
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(verifier))
	u.RawQuery = url.Values{"client_id": {c.ClientID}, "redirect_uri": {redirectURI}, "response_type": {"code"}, "scope": {OAuthScopes}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}}.Encode()
	return u.String(), nil
}

func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, verifier string) (TokenSet, error) {
	if code == "" || len(code) > 8192 || !validVerifier(verifier) {
		return TokenSet{}, errors.New("invalid OAuth authorization response")
	}
	if err := validateRedirect(redirectURI); err != nil {
		return TokenSet{}, err
	}
	return c.exchange(ctx, url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}, TokenSet{Scope: OAuthScopes})
}

// Refresh preserves a refresh token omitted from a successful response. Callers
// must serialize refreshes and atomically save the returned rotating token.
func (c *Client) Refresh(ctx context.Context, current TokenSet) (TokenSet, error) {
	if current.RefreshToken == "" {
		return TokenSet{}, errors.New("Cloudflare authorization must be renewed")
	}
	return c.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {current.RefreshToken}}, current)
}

func (c *Client) exchange(ctx context.Context, form url.Values, previous TokenSet) (TokenSet, error) {
	if err := c.validateClient(); err != nil {
		return TokenSet{}, err
	}
	u, err := endpoint(c.OAuthBaseURL, "/token")
	if err != nil {
		return TokenSet{}, err
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
	}
	if err = c.request(ctx, "exchange Cloudflare authorization", http.MethodPost, u, "", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, &response); err != nil {
		return TokenSet{}, err
	}
	if response.AccessToken == "" || response.ExpiresIn <= 0 || response.ExpiresIn > 366*24*60*60 || (response.TokenType != "" && !strings.EqualFold(response.TokenType, "Bearer")) {
		return TokenSet{}, errors.New("Cloudflare returned an invalid OAuth token response")
	}
	if response.RefreshToken == "" {
		response.RefreshToken = previous.RefreshToken
	}
	if response.Scope == "" {
		response.Scope = previous.Scope
	}
	return TokenSet{AccessToken: response.AccessToken, RefreshToken: response.RefreshToken, Scope: response.Scope, ExpiresAt: time.Now().UTC().Add(time.Duration(response.ExpiresIn) * time.Second)}, nil
}

func (c *Client) Revoke(ctx context.Context, token string) error {
	if err := c.validateClient(); err != nil {
		return err
	}
	if token == "" {
		return nil
	}
	u, err := endpoint(c.OAuthBaseURL, "/revoke")
	if err != nil {
		return err
	}
	form := url.Values{"client_id": {c.ClientID}, "token": {token}}
	return c.request(ctx, "revoke Cloudflare authorization", http.MethodPost, u, "", "application/x-www-form-urlencoded", []byte(form.Encode()), nil, nil)
}

type resultInfo struct {
	Page       int    `json:"page"`
	TotalPages int    `json:"total_pages"`
	PerPage    int    `json:"per_page"`
	TotalCount int    `json:"total_count"`
	Cursor     string `json:"cursor"`
}

type envelope[T any] struct {
	Success    bool       `json:"success"`
	Result     T          `json:"result"`
	ResultInfo resultInfo `json:"result_info"`
}

func (c *Client) Accounts(ctx context.Context, accessToken string) ([]Account, error) {
	accounts := []Account{}
	for page := 1; page <= maxPages; page++ {
		u, err := endpoint(c.APIBaseURL, "/accounts")
		if err != nil {
			return nil, err
		}
		u.RawQuery = url.Values{"page": {strconv.Itoa(page)}, "per_page": {"50"}}.Encode()
		var response envelope[[]Account]
		if err = c.api(ctx, "list Cloudflare accounts", http.MethodGet, u, accessToken, nil, nil, &response); err != nil {
			return nil, err
		}
		accounts = append(accounts, response.Result...)
		if pageDone(response.ResultInfo, page, len(response.Result), len(accounts)) {
			return accounts, nil
		}
	}
	return nil, errors.New("Cloudflare account list exceeded the pagination limit")
}

func (c *Client) Buckets(ctx context.Context, accessToken, accountID, jurisdiction string) ([]Bucket, error) {
	if !validID(accountID) || !ValidJurisdiction(jurisdiction) {
		return nil, errors.New("invalid Cloudflare account or R2 jurisdiction")
	}
	jurisdiction = normalizeJurisdiction(jurisdiction)
	buckets := []Bucket{}
	cursor := ""
	seen := make(map[string]bool)
	for page := 0; page < maxPages; page++ {
		u, err := endpoint(c.APIBaseURL, "/accounts/"+accountID+"/r2/buckets")
		if err != nil {
			return nil, err
		}
		query := url.Values{"per_page": {"1000"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		u.RawQuery = query.Encode()
		var response envelope[struct {
			Buckets []Bucket `json:"buckets"`
		}]
		if err = c.api(ctx, "list R2 buckets", http.MethodGet, u, accessToken, nil, map[string]string{"cf-r2-jurisdiction": jurisdiction}, &response); err != nil {
			return nil, err
		}
		for _, bucket := range response.Result.Buckets {
			if bucket.Jurisdiction == "" {
				bucket.Jurisdiction = jurisdiction
			}
			buckets = append(buckets, bucket)
		}
		cursor = response.ResultInfo.Cursor
		if cursor == "" {
			return buckets, nil
		}
		if seen[cursor] || len(response.Result.Buckets) == 0 {
			return nil, errors.New("Cloudflare returned an invalid bucket pagination cursor")
		}
		seen[cursor] = true
	}
	return nil, errors.New("R2 bucket list exceeded the pagination limit")
}

func pageDone(info resultInfo, page, count, total int) bool {
	if count == 0 {
		return true
	}
	if info.TotalPages > 0 {
		return page >= info.TotalPages
	}
	if info.TotalCount > 0 {
		return total >= info.TotalCount
	}
	return info.PerPage == 0 || count < info.PerPage
}

type permissionGroup struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	IsSelectable *bool    `json:"is_selectable"`
	Scopes       []string `json:"scopes"`
}

func (c *Client) bucketWritePermission(ctx context.Context, accessToken, accountID string) (string, error) {
	total := 0
	for page := 1; page <= maxPages; page++ {
		u, err := endpoint(c.APIBaseURL, "/accounts/"+accountID+"/tokens/permission_groups")
		if err != nil {
			return "", err
		}
		// This endpoint documents name/scope filters rather than pagination
		// parameters. An exact permission filter keeps provisioning independent
		// of the account's much larger permission catalog.
		u.RawQuery = url.Values{"name": {"Workers R2 Storage Bucket Item Write"}, "scope": {"com.cloudflare.edge.r2.bucket"}}.Encode()
		var response envelope[[]permissionGroup]
		if err = c.api(ctx, "read R2 credential permissions", http.MethodGet, u, accessToken, nil, nil, &response); err != nil {
			return "", err
		}
		for _, group := range response.Result {
			if group.Name == "Workers R2 Storage Bucket Item Write" {
				idValid := validID(group.ID)
				scopeValid := len(group.Scopes) == 1 && group.Scopes[0] == "com.cloudflare.edge.r2.bucket"
				c.diagnose(DiagnosticEvent{Operation: "read R2 credential permissions", Phase: "permission_group", Result: "advisory", PermissionIDLength: len(group.ID), PermissionIDValid: &idValid, PermissionSelectable: group.IsSelectable, PermissionScopeValid: &scopeValid})
				if !idValid || !scopeValid {
					return "", errors.New("Cloudflare returned an invalid R2 object permission group")
				}
				// The catalog's is_selectable field is advisory. Cloudflare's
				// Create Token endpoint performs the authoritative permission check;
				// the client must not reject a valid bucket-scoped group beforehand.
				return group.ID, nil
			}
		}
		total += len(response.Result)
		if pageDone(response.ResultInfo, page, len(response.Result), total) {
			break
		}
	}
	return "", errors.New("Cloudflare authorization does not include R2 bucket object write permission")
}

func (c *Client) CreateCredentials(ctx context.Context, accessToken, accountID, jurisdiction, bucket, name string, expiresAt time.Time) (Credentials, error) {
	if !validID(accountID) || !ValidJurisdiction(jurisdiction) || !validBucket(bucket) || name == "" || len(name) > 120 {
		return Credentials{}, errors.New("invalid R2 credential configuration")
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now().Add(time.Minute)) {
		return Credentials{}, errors.New("R2 credentials require a future expiration time")
	}
	groupID, err := c.bucketWritePermission(ctx, accessToken, accountID)
	if err != nil {
		return Credentials{}, err
	}
	u, err := endpoint(c.APIBaseURL, "/accounts/"+accountID+"/tokens")
	if err != nil {
		return Credentials{}, err
	}
	resource := "com.cloudflare.edge.r2.bucket." + accountID + "_" + normalizeJurisdiction(jurisdiction) + "_" + bucket
	body := map[string]any{"name": name, "expires_on": expiresAt.UTC().Format(time.RFC3339), "policies": []any{map[string]any{"effect": "allow", "resources": map[string]string{resource: "*"}, "permission_groups": []any{map[string]string{"id": groupID}}}}}
	var response envelope[struct {
		ID        string    `json:"id"`
		Value     string    `json:"value"`
		ExpiresOn time.Time `json:"expires_on"`
	}]
	if err = c.api(ctx, "create R2 credentials", http.MethodPost, u, accessToken, body, nil, &response); err != nil {
		return Credentials{}, err
	}
	if !validID(response.Result.ID) || response.Result.Value == "" {
		return Credentials{}, errors.New("Cloudflare returned incomplete R2 credentials")
	}
	secret := sha256.Sum256([]byte(response.Result.Value))
	if !response.Result.ExpiresOn.IsZero() {
		expiresAt = response.Result.ExpiresOn
	}
	return Credentials{TokenID: response.Result.ID, AccessKeyID: response.Result.ID, SecretAccessKey: hex.EncodeToString(secret[:]), ExpiresAt: expiresAt.UTC()}, nil
}

func (c *Client) DeleteToken(ctx context.Context, accessToken, accountID, tokenID string) error {
	if !validID(accountID) || !validID(tokenID) {
		return errors.New("invalid Cloudflare account or token identifier")
	}
	u, err := endpoint(c.APIBaseURL, "/accounts/"+accountID+"/tokens/"+tokenID)
	if err != nil {
		return err
	}
	var response envelope[struct {
		ID string `json:"id"`
	}]
	err = c.api(ctx, "delete R2 credentials", http.MethodDelete, u, accessToken, nil, nil, &response)
	// A retried cleanup can refer to a token whose first deletion succeeded but
	// whose local metadata commit failed. Only explicit Not Found is idempotent;
	// authorization failures must remain visible so cleanup can be retried.
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

// Endpoint returns the S3 endpoint for an account's buckets. It keeps
// jurisdiction-specific namespace identity stable across OAuth and manually
// configured S3 connections.
func Endpoint(accountID, jurisdiction string) (string, error) {
	if !validID(accountID) || !ValidJurisdiction(jurisdiction) {
		return "", errors.New("invalid Cloudflare account or R2 jurisdiction")
	}
	part := ""
	if jurisdiction = normalizeJurisdiction(jurisdiction); jurisdiction != "default" {
		part = "." + jurisdiction
	}
	return "https://" + accountID + part + ".r2.cloudflarestorage.com", nil
}

func ValidJurisdiction(value string) bool {
	return value == "" || value == "default" || value == "eu" || value == "fedramp" || value == "us"
}

func normalizeJurisdiction(value string) string {
	if value == "" {
		return "default"
	}
	return value
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validBucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
			return false
		}
	}
	return true
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && !strings.ContainsRune("-._~", char) {
			return false
		}
	}
	return true
}

func validateRedirect(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return errors.New("OAuth requires a registered HTTPS or localhost callback URL")
	}
	return nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func endpoint(base, path string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return nil, errors.New("invalid Cloudflare API endpoint")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u, nil
}

func (c *Client) validateClient() error {
	if c.ClientID == "" || len(c.ClientID) > 256 || strings.ContainsAny(c.ClientID, "\r\n\t ") {
		return errors.New("Cloudflare OAuth client ID is not configured")
	}
	return nil
}

type APIError struct {
	Operation  string
	StatusCode int
	Codes      []int
	OAuthError string
	CFRay      string
}

func (e *APIError) Error() string {
	message := "Cloudflare could not " + e.Operation
	switch e.StatusCode {
	case http.StatusUnauthorized:
		message = "Cloudflare authorization expired or was revoked; connect again"
	case http.StatusForbidden:
		message = "Cloudflare denied access; check the selected account, OAuth scopes, and API Token Provisioning role"
	case http.StatusTooManyRequests:
		message = "Cloudflare rate limit reached; try again later"
	}
	if e.OAuthError == "invalid_grant" {
		message = "Cloudflare authorization expired or was revoked; connect again"
	}
	details := strconv.Itoa(e.StatusCode)
	if len(e.Codes) > 0 {
		codes := make([]string, 0, len(e.Codes))
		for _, code := range e.Codes {
			codes = append(codes, strconv.Itoa(code))
		}
		details += "; Cloudflare codes " + strings.Join(codes, ",")
	}
	if ray := diagnosticRay(e.CFRay); ray != "" {
		details += "; CF-Ray " + ray
	}
	return fmt.Sprintf("%s (HTTP %s)", message, details)
}

func (c *Client) api(ctx context.Context, operation, method string, u *url.URL, token string, body any, headers map[string]string, result any) error {
	if token == "" {
		return errors.New("Cloudflare authorization is missing; connect again")
	}
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("invalid Cloudflare request")
		}
	}
	var raw json.RawMessage
	metadata, err := c.requestWithMetadata(ctx, operation, method, u, token, "application/json", data, headers, &raw)
	if err != nil {
		return err
	}
	var status struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code int `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(raw, &status) != nil {
		c.diagnose(DiagnosticEvent{Operation: operation, Phase: "api_result", Method: method, HTTPStatus: metadata.status, CFRay: metadata.ray, Result: "invalid_response"})
		return errors.New("Cloudflare returned an invalid API response")
	}
	if !status.Success {
		apiErr := &APIError{Operation: operation, StatusCode: metadata.status, CFRay: metadata.ray}
		for _, item := range status.Errors {
			apiErr.Codes = append(apiErr.Codes, item.Code)
		}
		c.diagnose(DiagnosticEvent{Operation: operation, Phase: "api_result", Method: method, HTTPStatus: metadata.status, ErrorCodes: apiErr.Codes, CFRay: metadata.ray, Result: "api_error"})
		return apiErr
	}
	if result != nil && json.Unmarshal(raw, result) != nil {
		c.diagnose(DiagnosticEvent{Operation: operation, Phase: "api_result", Method: method, HTTPStatus: metadata.status, CFRay: metadata.ray, Result: "invalid_response"})
		return errors.New("Cloudflare returned an invalid API result")
	}
	c.diagnose(DiagnosticEvent{Operation: operation, Phase: "api_result", Method: method, HTTPStatus: metadata.status, CFRay: metadata.ray, Result: "success"})
	return nil
}

func (c *Client) request(ctx context.Context, operation, method string, u *url.URL, token, contentType string, body []byte, headers map[string]string, result any) error {
	_, err := c.requestWithMetadata(ctx, operation, method, u, token, contentType, body, headers, result)
	return err
}

type responseMetadata struct {
	status int
	ray    string
}

func (c *Client) requestWithMetadata(ctx context.Context, operation, method string, u *url.URL, token, contentType string, body []byte, headers map[string]string, result any) (metadata responseMetadata, returnedErr error) {
	started := time.Now()
	outcome := "success"
	c.diagnose(DiagnosticEvent{Operation: operation, Phase: "request_started", Method: method, Result: "pending"})
	defer func() {
		var apiErr *APIError
		var codes []int
		if errors.As(returnedErr, &apiErr) {
			codes = apiErr.Codes
		}
		c.diagnose(DiagnosticEvent{Operation: operation, Phase: "request_completed", Method: method, HTTPStatus: metadata.status, ErrorCodes: codes, CFRay: metadata.ray, DurationMS: time.Since(started).Milliseconds(), Result: outcome})
	}()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		outcome = "invalid_request"
		return metadata, errors.New("invalid Cloudflare request")
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	client := http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		client = *c.HTTPClient
	}
	// No redirect may forward the OAuth form, bearer token, or provisioning body.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			outcome = "canceled"
			return metadata, ctx.Err()
		}
		outcome = "network_error"
		return metadata, errors.New("Cloudflare request failed; check the network connection and try again")
	}
	metadata.status, metadata.ray = response.StatusCode, diagnosticRay(response.Header.Get("CF-Ray"))
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			outcome = "canceled"
			return metadata, ctx.Err()
		}
		outcome = "read_error"
		return metadata, errors.New("cannot read Cloudflare response")
	}
	if len(data) > maxResponseBytes {
		outcome = "response_too_large"
		return metadata, errors.New("Cloudflare response exceeded the size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		outcome = "http_error"
		apiErr := &APIError{Operation: operation, StatusCode: response.StatusCode, CFRay: metadata.ray}
		var details struct {
			Error  string `json:"error"`
			Errors []struct {
				Code int `json:"code"`
			} `json:"errors"`
		}
		if json.Unmarshal(data, &details) == nil {
			// Only a bounded known OAuth identifier is retained. Server-provided
			// descriptions/messages can echo request secrets and are never logged.
			switch details.Error {
			case "invalid_grant", "invalid_client", "invalid_scope", "access_denied":
				apiErr.OAuthError = details.Error
			}
			for _, item := range details.Errors {
				apiErr.Codes = append(apiErr.Codes, item.Code)
			}
		}
		return metadata, apiErr
	}
	if result != nil && json.Unmarshal(data, result) != nil {
		outcome = "invalid_response"
		return metadata, errors.New("Cloudflare returned an invalid JSON response")
	}
	return metadata, nil
}
