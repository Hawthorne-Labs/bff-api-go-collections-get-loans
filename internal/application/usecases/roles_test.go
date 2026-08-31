package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
)

type fakeProvisioner struct {
	created  bool
	err      error
	calls    int
	lastCode string
}

func (f *fakeProvisioner) EnsureGroup(_ context.Context, code, _ string) (bool, error) {
	f.calls++
	f.lastCode = code
	if f.err != nil {
		return false, f.err
	}
	return f.created, nil
}

type fakeRoleCore struct {
	createResp  map[string]any
	createErr   error
	updateCalls []map[string]any
	updateErr   error
}

func (f *fakeRoleCore) ListRoles(context.Context, string, string, string, bool) (map[string]any, error) {
	return nil, nil
}
func (f *fakeRoleCore) GetRole(context.Context, string, string, string, string) (map[string]any, error) {
	return nil, nil
}
func (f *fakeRoleCore) CreateRole(_ context.Context, _, _, _ string, body map[string]any) (map[string]any, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createResp != nil {
		return f.createResp, nil
	}
	return map[string]any{
		"code":         body["code"],
		"display_name": body["displayName"],
		"description":  body["description"],
		"is_active":    true,
	}, nil
}
func (f *fakeRoleCore) UpdateRole(_ context.Context, _ string, _, _, _ string, body map[string]any) (map[string]any, error) {
	f.updateCalls = append(f.updateCalls, body)
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return body, nil
}
func (f *fakeRoleCore) ReplaceRolePermissions(context.Context, string, string, string, string, map[string]any) (map[string]any, error) {
	return nil, nil
}
func (f *fakeRoleCore) ListPermissions(context.Context, string, string, string, string) (map[string]any, error) {
	return nil, nil
}
func (f *fakeRoleCore) ListRoleAuditLog(context.Context, string, string, string, string, int) (map[string]any, error) {
	return map[string]any{"items": []any{}}, nil
}

func TestCreateRoleProvisionsCognitoGroup(t *testing.T) {
	core := &fakeRoleCore{}
	prov := &fakeProvisioner{created: true}
	uc := NewRolesUsecase(core, prov)

	out, err := uc.CreateRole(context.Background(), "t1", "default", "admin@x", map[string]any{
		"code":         "coach",
		"display_name": "Coach",
		"description":  "Coach Cobranza",
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	meta, _ := out["cognito"].(map[string]any)
	if meta["group"] != "coach" || meta["created"] != true {
		t.Fatalf("cognito meta=%v", meta)
	}
	if prov.calls != 1 || prov.lastCode != "coach" {
		t.Fatalf("provisioner calls=%d code=%q", prov.calls, prov.lastCode)
	}
}

func TestCreateRoleCompensatesWhenCognitoFails(t *testing.T) {
	core := &fakeRoleCore{}
	prov := &fakeProvisioner{err: errors.New("cognito down")}
	uc := NewRolesUsecase(core, prov)

	_, err := uc.CreateRole(context.Background(), "t1", "default", "admin@x", map[string]any{
		"code":         "coach",
		"displayName":  "Coach",
		"description":  "Coach Cobranza",
	})
	if err == nil {
		t.Fatal("expected cognito compensation error")
	}
	biz, ok := err.(*domain.BusinessError)
	if !ok || biz.Code != domain.RoleMutationFailed {
		t.Fatalf("err=%v", err)
	}
	if len(core.updateCalls) != 1 {
		t.Fatalf("updateCalls=%d want 1", len(core.updateCalls))
	}
	active, _ := core.updateCalls[0]["isActive"].(bool)
	if active {
		t.Fatalf("compensation isActive=%v want false", core.updateCalls[0]["isActive"])
	}
}

func TestNormalizeRoleWriteBodyMapsSnakeCase(t *testing.T) {
	out := normalizeRoleWriteBody(map[string]any{
		"code":         "coach",
		"display_name": "Coach",
		"is_active":    true,
	})
	if out["displayName"] != "Coach" {
		t.Fatalf("displayName=%v", out["displayName"])
	}
	if out["isActive"] != true {
		t.Fatalf("isActive=%v", out["isActive"])
	}
}
