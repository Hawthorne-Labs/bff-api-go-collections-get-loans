package domain

// Error codes — numeric public catalog parity with Python
// mvp/bff-api-python-collections-get-loans/app/interface/api/errors.py (_PUBLIC_ERROR_CODES).
// anti-regresion: BUG-1008 ver handoffs/regressions.md (no revertir sin leer)
const (
	ClientsListFailed              = 10001
	UsersListFailed                = 10002
	UserCreateFailed               = 10003
	UserTenantsListFailed          = 10004
	StrategySegmentationFailed     = 10005
	StrategyAssignmentsListFailed  = 10006
	StrategyAssignmentCreateFailed = 10007
	StrategyQueueCleanFailed       = 10008
	AtRiskClientsListFailed        = 10009
	ClientContactsListFailed       = 10010
	LoansListFailed                = 10011
	LoanDetailLoadFailed           = 10012
	LoanDetailTimeout              = 10013
	LoanBalanceLoadFailed          = 10014
	LoanPaymentPlanLoad            = 10015
	LoanStatementLoad              = 10016
	ContactSubmitFail              = 10017
	UserPermissionsLoad       = 10019
	RolesListFailed           = 10020
	RoleMutationFailed        = 10021
	UserLastLoginRecord       = 90018
	CollectionsRequestFailed  = 90018

	MissingAuthToken = 90001
	InvalidAuthToken = 90002
	AccessDenied     = 90004
	ValidationFailed = 90005
)

// BusinessError represents a user-facing error with a numeric code.
type BusinessError struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

func (e *BusinessError) Error() string {
	return e.Message
}

// NewBusinessError creates a BusinessError from a code and message.
func NewBusinessError(code int, message string) *BusinessError {
	return &BusinessError{Code: code, Message: message}
}

// NewHTTPBusinessError creates a BusinessError with an explicit HTTP status.
func NewHTTPBusinessError(httpStatus, code int, message string) *BusinessError {
	return &BusinessError{Code: code, Message: message, HTTPStatus: httpStatus}
}

// Status returns the HTTP status for this error.
func (e *BusinessError) Status() int {
	if e == nil {
		return 502
	}
	if e.HTTPStatus > 0 {
		return e.HTTPStatus
	}
	switch e.Code {
	case MissingAuthToken, InvalidAuthToken:
		return 401
	case AccessDenied:
		return 403
	case ValidationFailed:
		return 422
	default:
		return 502
	}
}
