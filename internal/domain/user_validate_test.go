package domain

import "testing"

func TestCreateUserAdminAllowsEmptyTenant(t *testing.T) {
	req := CreateUserRequest{Email: "a@b.com", Nombre: "Admin", Rol: "admin"}
	if err := req.NormalizeAndValidate(); err != nil {
		t.Fatalf("admin empty tenant should pass: %v", err)
	}
}

func TestCreateUserAgentRequiresTenant(t *testing.T) {
	req := CreateUserRequest{Email: "a@b.com", Nombre: "Agent", Rol: "agent"}
	if err := req.NormalizeAndValidate(); err == nil {
		t.Fatal("expected tenant required")
	}
}

func TestCreateUserAdminMultiTenantOK(t *testing.T) {
	req := CreateUserRequest{
		Email: "a@b.com", Nombre: "Admin", Rol: "admin",
		Tenants: []string{"PRESTAYA", "PRESTAAUTO"},
	}
	if err := req.NormalizeAndValidate(); err != nil {
		t.Fatalf("admin multi tenant: %v", err)
	}
	if req.Tenant != "PRESTAYA" {
		t.Fatalf("primary tenant=%q", req.Tenant)
	}
}

func TestCreateUserAgentMultiTenantRejected(t *testing.T) {
	req := CreateUserRequest{
		Email: "a@b.com", Nombre: "Agent", Rol: "agent", Tenant: "PRESTAYA",
		Tenants: []string{"PRESTAYA", "PRESTAAUTO"},
	}
	if err := req.NormalizeAndValidate(); err == nil {
		t.Fatal("expected multi-tenant reject for agent")
	}
}
