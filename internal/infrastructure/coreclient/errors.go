package coreclient

import (
	"encoding/json"
	"net/http"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

// translateCoreError converts an HTTP status code + response body to a BusinessError.
func translateCoreError(statusCode int, body []byte) *domain.BusinessError {
	detail := parseCoreErrorMessage(body)
	code := parseCoreErrorCode(body)

	switch statusCode {
	case http.StatusGatewayTimeout:
		return &domain.BusinessError{
			Code:    domain.LoanDetailTimeout,
			Message: detail,
		}
	case http.StatusNotFound:
		return &domain.BusinessError{
			Code:    code,
			Message: detail,
		}
	case http.StatusConflict:
		return &domain.BusinessError{
			Code:    code,
			Message: detail,
		}
	case http.StatusForbidden:
		return &domain.BusinessError{
			Code:    domain.AccessDenied,
			Message: "No tiene permisos para realizar esta acción.",
		}
	case http.StatusBadRequest:
		return &domain.BusinessError{
			Code:    code,
			Message: detail,
		}
	default:
		return &domain.BusinessError{
			Code:    domain.CollectionsRequestFailed,
			Message: detail,
		}
	}
}

// parseCoreErrorMessage extracts an error message from the core response body.
func parseCoreErrorMessage(body []byte) string {
	if len(body) == 0 {
		return "No se pudo completar la solicitud."
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return string(body)
	}

	// Check for detail field
	if detail, ok := result["detail"].(string); ok && detail != "" {
		return detail
	}
	if message, ok := result["message"].(string); ok && message != "" {
		return message
	}

	// Check for nested error object
	if nested, ok := result["error"].(map[string]any); ok {
		if message, ok := nested["message"].(string); ok && message != "" {
			return message
		}
		if detail, ok := nested["detail"].(string); ok && detail != "" {
			return detail
		}
	}

	return "No se pudo completar la solicitud."
}

// parseCoreErrorCode extracts a numeric code from the core response body.
func parseCoreErrorCode(body []byte) int {
	if len(body) == 0 {
		return domain.CollectionsRequestFailed
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return domain.CollectionsRequestFailed
	}

	// Check for error_code field
	if code, ok := result["error_code"].(float64); ok {
		return int(code)
	}
	if code, ok := result["code"].(float64); ok {
		return int(code)
	}

	// Check for nested error code
	if nested, ok := result["error"].(map[string]any); ok {
		if code, ok := nested["code"].(float64); ok {
			return int(code)
		}
	}

	// Check extensions
	if extensions, ok := result["extensions"].(map[string]any); ok {
		if code, ok := extensions["code"].(float64); ok {
			return int(code)
		}
	}

	return domain.CollectionsRequestFailed
}
