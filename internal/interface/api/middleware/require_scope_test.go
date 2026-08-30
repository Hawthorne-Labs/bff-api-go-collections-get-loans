package middleware

import (
	"reflect"
	"testing"
)

func TestSplitWordsSplitsOnSpaces(t *testing.T) {
	got := splitWords("collections:read collections:write")
	want := []string{"collections:read", "collections:write"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitWords = %#v, want %#v", got, want)
	}
}

func TestSplitScopeUsesSpaceSeparatedScopes(t *testing.T) {
	got := splitScope("collections:read collections:write")
	want := []string{"collections:read", "collections:write"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitScope = %#v, want %#v", got, want)
	}
	if !hasScope(got, "collections:read") {
		t.Error("expected collections:read to be present")
	}
}
