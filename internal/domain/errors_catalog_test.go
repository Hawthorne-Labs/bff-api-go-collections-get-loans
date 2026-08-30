package domain

import "testing"

func TestPublicErrorCodesMatchPythonCatalog(t *testing.T) {
	// anti-regresion: BUG-1008
	cases := map[string]int{
		"MissingAuthToken":   MissingAuthToken,
		"InvalidAuthToken":   InvalidAuthToken,
		"AccessDenied":       AccessDenied,
		"ClientsListFailed":  ClientsListFailed,
		"LoansListFailed":    LoansListFailed,
		"RolesListFailed":    RolesListFailed,
		"ValidationFailed":   ValidationFailed,
	}
	want := map[string]int{
		"MissingAuthToken":  90001,
		"InvalidAuthToken":  90002,
		"AccessDenied":      90004,
		"ClientsListFailed": 10001,
		"LoansListFailed":   10011,
		"RolesListFailed":   10020,
		"ValidationFailed":  90005,
	}
	for name, got := range cases {
		if got != want[name] {
			t.Fatalf("%s=%d want %d", name, got, want[name])
		}
	}
}
