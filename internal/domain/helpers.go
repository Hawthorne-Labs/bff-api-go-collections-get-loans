package domain

import "strings"

// MaskPhone masks a phone number: keeps country prefix + last 4 digits.
// Examples:
//
//	'+521234567890' → '+52···7890'
//	'5551234567'    → '···4567'
//	nil             → nil
func MaskPhone(phone *string) *string {
	if phone == nil || *phone == "" {
		return phone
	}
	p := *phone
	digits := strings.TrimPrefix(p, "+")
	prefix := ""
	if strings.HasPrefix(p, "+") && len(digits) >= 2 {
		prefix = "+" + digits[:2]
	}
	last4 := ""
	if len(p) >= 4 {
		last4 = p[len(p)-4:]
	} else {
		last4 = p
	}
	s := prefix + "···" + last4
	return &s
}

// MaskEmail masks an email: keeps first char + '···' + '@domain'.
// Examples:
//
//	'john.doe@example.com' → 'j···@example.com'
//	'a@b.com'              → 'a···@b.com'
//	nil                    → nil
func MaskEmail(email *string) *string {
	if email == nil || *email == "" {
		return email
	}
	e := *email
	atIdx := strings.Index(e, "@")
	if atIdx == -1 {
		return &e
	}
	local := e[:atIdx]
	domain := e[atIdx:] // includes @
	visible := ""
	if len(local) > 0 {
		visible = string(local[0])
	}
	s := visible + "···" + domain
	return &s
}
