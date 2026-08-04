package domain

// LoanDetailDTO represents complete loan detail with nested client/vehicle/payment promises.
type LoanDetailDTO struct {
	LoanID             string              `json:"loan_id"`
	Status             *string             `json:"status,omitempty"`
	Principal          *float64            `json:"principal,omitempty"`
	OutstandingBalance *float64            `json:"outstanding_balance,omitempty"`
	InterestRate       *float64            `json:"interest_rate,omitempty"`
	Client             *ClientDTO          `json:"client,omitempty"`
	Vehicle            *VehicleDTO         `json:"vehicle,omitempty"`
	PaymentPromises    []PaymentPromiseDTO `json:"payment_promises"`
}

// LoanBalanceDTO represents loan balance breakdown (capital vencido, intereses, mora).
type LoanBalanceDTO struct {
	LoanID         string       `json:"loan_id"`
	CapitalVencido *float64     `json:"capital_vencido,omitempty"`
	Intereses      *float64     `json:"intereses,omitempty"`
	MoraBucket     []MoraBucket `json:"mora_bucket,omitempty"`
	Total          *float64     `json:"total,omitempty"`
}

// MoraBucket represents a single bucket in the mora breakdown.
type MoraBucket struct {
	Days   int     `json:"days"`
	Amount float64 `json:"amount"`
}

// InstallmentDTO represents a single installment in the amortization schedule.
type InstallmentDTO struct {
	InstallmentNumber int      `json:"installment_number"`
	DueDate           string   `json:"due_date"`
	Principal         *float64 `json:"principal,omitempty"`
	Interest          *float64 `json:"interest,omitempty"`
	Total             *float64 `json:"total,omitempty"`
	Status            *string  `json:"status,omitempty"`
}

// LoanStatementLineDTO represents a single entry in the loan statement/history.
type LoanStatementLineDTO struct {
	EntryDate       string   `json:"entry_date"`
	Description     *string  `json:"description,omitempty"`
	TransactionType *string  `json:"transaction_type,omitempty"`
	Amount          *float64 `json:"amount,omitempty"`
	Balance         *float64 `json:"balance,omitempty"`
}
