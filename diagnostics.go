package r2connect

import "net/http"

// DiagnosticEvent deliberately contains only an allowlist of operational data.
// It cannot carry request URLs, credentials, response messages or payloads.
type DiagnosticEvent struct {
	Operation            string `json:"operation"`
	Phase                string `json:"phase"`
	Method               string `json:"method,omitempty"`
	HTTPStatus           int    `json:"httpStatus,omitempty"`
	ErrorCodes           []int  `json:"errorCodes,omitempty"`
	CFRay                string `json:"cfRay,omitempty"`
	DurationMS           int64  `json:"durationMs,omitempty"`
	Result               string `json:"result"`
	PermissionIDLength   int    `json:"permissionIdLength,omitempty"`
	PermissionIDValid    *bool  `json:"permissionIdValid,omitempty"`
	PermissionSelectable *bool  `json:"permissionSelectable,omitempty"`
	PermissionScopeValid *bool  `json:"permissionScopeValid,omitempty"`
}

func diagnosticOperation(value string) string {
	switch value {
	case "exchange Cloudflare authorization", "revoke Cloudflare authorization", "list Cloudflare accounts", "list R2 buckets", "read R2 credential permissions", "create R2 credentials", "delete R2 credentials":
		return value
	default:
		return "Cloudflare request"
	}
}

// Cloudflare Ray IDs have a hexadecimal request ID and optional airport code.
// Reject arbitrary header values rather than trying to redact unknown secrets.
func diagnosticRay(value string) string {
	if len(value) != 16 && len(value) != 20 {
		return ""
	}
	for _, ch := range value[:16] {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F') {
			return ""
		}
	}
	if len(value) == 20 {
		if value[16] != '-' {
			return ""
		}
		for _, ch := range value[17:] {
			if ch < 'A' || ch > 'Z' {
				return ""
			}
		}
	}
	return value
}

func (c *Client) diagnose(event DiagnosticEvent) {
	if c.Diagnostic == nil {
		return
	}
	event.Operation = diagnosticOperation(event.Operation)
	switch event.Phase {
	case "request_started", "request_completed", "permission_group", "api_result":
	default:
		return
	}
	switch event.Result {
	case "pending", "success", "http_error", "api_error", "network_error", "canceled", "invalid_response", "response_too_large", "read_error", "invalid_request", "advisory":
	default:
		return
	}
	switch event.Method {
	case "", http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		event.Method = "OTHER"
	}
	event.CFRay = diagnosticRay(event.CFRay)
	if len(event.ErrorCodes) > 20 {
		event.ErrorCodes = event.ErrorCodes[:20]
	}
	event.ErrorCodes = append([]int(nil), event.ErrorCodes...)
	c.Diagnostic(event)
}
