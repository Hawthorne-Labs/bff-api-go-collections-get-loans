package usecases

import (
	"context"
	"testing"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/cognito"
)

type fakeUsersCore struct {
	listed  map[string]any
	created map[string]any
	updates []map[string]any
}

func (f *fakeUsersCore) ListUsers(context.Context, string, string, string) (map[string]any, error) {
	return f.listed, nil
}
func (f *fakeUsersCore) CreateUser(_ context.Context, _, _, _ string, body map[string]any) (map[string]any, error) {
	if body["activo"] != false {
		tPanic("create must stage activo=false")
	}
	return f.created, nil
}
func (f *fakeUsersCore) UpdateUser(_ context.Context, userID, _, _, _ string, body map[string]any) (map[string]any, error) {
	cp := map[string]any{"id": userID}
	for k, v := range body {
		cp[k] = v
	}
	f.updates = append(f.updates, cp)
	return cp, nil
}
func (f *fakeUsersCore) RecordLastLogin(context.Context, string, string, string) error { return nil }
func (f *fakeUsersCore) GetMyPermissions(context.Context, string, string, string) (map[string]any, error) {
	return map[string]any{"role": "admin"}, nil
}
func (f *fakeUsersCore) ListMyTenants(context.Context, string, string, string) (map[string]any, error) {
	return map[string]any{"items": []any{}}, nil
}
func (f *fakeUsersCore) ListTenantSyncStatus(context.Context, string, string, string) (map[string]any, error) {
	return map[string]any{}, nil
}

func tPanic(msg string) { panic(msg) }

type fakeIdentity struct {
	syncN  int
	resetN int
}

func (f *fakeIdentity) AdminSyncUser(context.Context, string, string, string, bool) (cognito.ProvisioningResult, error) {
	f.syncN++
	pwd := "Temp1!abcdef"
	role := "agent"
	return cognito.ProvisioningResult{
		Provisioned: true, Status: "created", TemporaryPassword: &pwd,
		RequiresPasswordChange: true, Group: &role,
	}, nil
}
func (f *fakeIdentity) AdminResetOrSyncUser(context.Context, string, string, string, bool) (cognito.ProvisioningResult, error) {
	f.resetN++
	pwd := "Reset1!abcdef"
	role := "admin"
	return cognito.ProvisioningResult{
		Provisioned: true, Status: "password_reset", TemporaryPassword: &pwd,
		RequiresPasswordChange: true, Group: &role,
	}, nil
}

func TestUserIdentitySagaCreateAttachesCognito(t *testing.T) {
	core := &fakeUsersCore{created: map[string]any{"data": map[string]any{"id": "u-1"}}}
	id := &fakeIdentity{}
	uc := NewUsersUsecase(core, id)
	out, err := uc.CreateUser(context.Background(), "t", "default", "admin@x.com", map[string]any{
		"email": "agent@x.com", "nombre": "Agent", "rol": "agent", "tenant": "PRESTAYA",
	})
	if err != nil {
		t.Fatal(err)
	}
	cog, _ := out["cognito"].(map[string]any)
	if cog["status"] != "created" || id.syncN != 1 || len(core.updates) != 1 {
		t.Fatalf("out=%#v sync=%d updates=%d", out, id.syncN, len(core.updates))
	}
	if core.updates[0]["activo"] != true {
		t.Fatalf("activation update missing: %#v", core.updates[0])
	}
}

func TestResetPasswordMatchesUserIDAndEmail(t *testing.T) {
	core := &fakeUsersCore{listed: map[string]any{"items": []any{
		map[string]any{"id": "u-9", "email": "Admin@X.com", "nombre": "A", "rol": "admin", "activo": true},
	}}}
	id := &fakeIdentity{}
	uc := NewUsersUsecase(core, id)
	out, err := uc.ResetPassword(context.Background(), "u-9", "admin@x.com", "t", "default", "actor@x.com")
	if err != nil {
		t.Fatal(err)
	}
	cog := out["cognito"].(map[string]any)
	if cog["status"] != "password_reset" || id.resetN != 1 {
		t.Fatalf("%#v", out)
	}
}
