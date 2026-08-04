package domain

// Error codes for the get-loans BFF.
// These are numeric application codes mapped from the Python BFF error codes.
const (
	// Clients
	ClientsListFailed = 4001
	// Loans
	LoansListFailed       = 4010
	LoanDetailLoadFailed  = 4011
	LoanDetailTimeout     = 4012
	LoanBalanceLoadFailed = 4013
	LoanPaymentPlanLoad   = 4014
	LoanStatementLoad     = 4015
	// Strategy
	StrategySegmentationFailed     = 4020
	StrategyAssignmentsListFailed  = 4021
	StrategyAssignmentCreateFailed = 4022
	StrategyQueueCleanFailed       = 4023
	// Users
	UsersListFailed       = 4030
	UserCreateFailed      = 4031
	UserTenantsListFailed = 4032
	UserLastLoginRecord   = 4033
	UserPermissionsLoad   = 4034
	// General
	AtRiskClientsListFailed  = 4040
	ClientContactsListFailed = 4041
	CollectionsRequestFailed = 4050
	// Auth
	MissingAuthToken  = 4060
	InvalidAuthToken  = 4061
	AccessDenied      = 4062
	ContactSubmitFail = 4070
)

// BusinessError represents a user-facing error with a numeric code.
type BusinessError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *BusinessError) Error() string {
	return e.Message
}

// NewBusinessError creates a BusinessError from a code string.
func NewBusinessError(code int, message string) *BusinessError {
	return &BusinessError{Code: code, Message: message}
}
