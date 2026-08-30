package coreclient

import (
	"strings"
	"testing"
)

func TestEncodeQueryEscapesPhoneSearchSpaces(t *testing.T) {
	q := encodeQuery(map[string]string{
		"search":    "+504 9479-4882",
		"search_by": "telefono",
		"view":      "search",
	})
	if !strings.HasPrefix(q, "?") {
		t.Fatalf("expected ? prefix, got %q", q)
	}
	if strings.Contains(q, " ") {
		t.Fatalf("query must not contain raw spaces: %q", q)
	}
	if !strings.Contains(q, "search=") || !strings.Contains(q, "%2B504") && !strings.Contains(q, "+504") {
		// url.Values.Encode encodes + as %2B
		t.Fatalf("expected encoded phone search, got %q", q)
	}
	if !strings.Contains(q, "search_by=telefono") {
		t.Fatalf("missing search_by: %q", q)
	}
	// Space must be percent-encoded (%20) or as + in form encoding — never raw.
	if strings.Contains(q, "504 9479") {
		t.Fatalf("raw space leaked into query: %q", q)
	}
}

func TestEncodeQueryEmpty(t *testing.T) {
	if encodeQuery(nil) != "" || encodeQuery(map[string]string{}) != "" {
		t.Fatal("expected empty query")
	}
}
