package domain

// ClientDTO represents client information nested in loan detail responses.
// PII fields (email, phone, secondary_phones) are masked at the perimeter per ADR-0011.
type ClientDTO struct {
	ClientID        string   `json:"client_id"`
	Name            *string  `json:"name,omitempty"`
	Email           *string  `json:"email,omitempty"`
	Phone           *string  `json:"phone,omitempty"`
	SecondaryPhones []string `json:"secondary_phones,omitempty"`
}

// VehicleDTO represents vehicle information nested in loan detail.
type VehicleDTO struct {
	VehicleID *string `json:"vehicle_id,omitempty"`
	Plate     *string `json:"plate,omitempty"`
	Year      *int    `json:"year,omitempty"`
}

// PaymentPromiseDTO represents a payment promise record (no amount field per COB-109).
type PaymentPromiseDTO struct {
	PromiseID   string  `json:"promise_id"`
	PromiseDate string  `json:"promise_date"`
	Status      *string `json:"status,omitempty"`
	CreatedAt   *string `json:"created_at,omitempty"`
}
