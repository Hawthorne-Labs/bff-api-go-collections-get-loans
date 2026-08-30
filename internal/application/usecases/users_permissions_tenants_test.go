package usecases

import (
	"testing"
)

func TestMergePermissionsWithTenantsIncludesCoreItems(t *testing.T) {
	// anti-regresion: BUG-1007 — permissions without tenants forced SPA __admin__ → crypto 90109
	merged := mergePermissionsWithTenants(
		map[string]any{
			"email": "admin@example.com",
			"role":  "admin",
			"nombre": "Admin",
		},
		map[string]any{
			"items": []any{
				map[string]any{"id": "PRESTAYA"},
				map[string]any{"id": "PRESTAAUTO"},
			},
		},
	)

	tenants, ok := merged["tenants"].([]any)
	if !ok {
		t.Fatalf("tenants type: %T", merged["tenants"])
	}
	if len(tenants) != 2 {
		t.Fatalf("tenants len=%d want 2", len(tenants))
	}
	first, _ := tenants[0].(map[string]any)
	if first["id"] != "PRESTAYA" {
		t.Fatalf("first tenant id=%v", first["id"])
	}
	if merged["role"] != "admin" {
		t.Fatalf("role clobbered: %v", merged["role"])
	}
}

func TestMergePermissionsWithTenantsEmptyWhenCoreOmitsItems(t *testing.T) {
	merged := mergePermissionsWithTenants(map[string]any{"role": "admin"}, map[string]any{})
	tenants, ok := merged["tenants"].([]any)
	if !ok {
		t.Fatalf("tenants type: %T", merged["tenants"])
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty tenants, got %#v", tenants)
	}
}
