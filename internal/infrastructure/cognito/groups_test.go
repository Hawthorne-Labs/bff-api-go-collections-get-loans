package cognito

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/smithy-go"
)

type stubAPIError struct {
	code string
}

func (e stubAPIError) Error() string            { return e.code }
func (e stubAPIError) ErrorCode() string        { return e.code }
func (e stubAPIError) ErrorMessage() string     { return e.code }
func (e stubAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

type fakeGroupAPI struct {
	createCalls int
	deleteCalls int
	createErr   error
	deleteErr   error
	groups      map[string]struct{}
}

func (f *fakeGroupAPI) CreateGroup(ctx context.Context, params *cognitoidentityprovider.CreateGroupInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.CreateGroupOutput, error) {
	f.createCalls++
	name := ""
	if params.GroupName != nil {
		name = *params.GroupName
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.groups == nil {
		f.groups = map[string]struct{}{}
	}
	if _, ok := f.groups[name]; ok {
		return nil, stubAPIError{code: "GroupExistsException"}
	}
	f.groups[name] = struct{}{}
	return &cognitoidentityprovider.CreateGroupOutput{}, nil
}

func (f *fakeGroupAPI) DeleteGroup(ctx context.Context, params *cognitoidentityprovider.DeleteGroupInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DeleteGroupOutput, error) {
	f.deleteCalls++
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	name := ""
	if params.GroupName != nil {
		name = *params.GroupName
	}
	delete(f.groups, name)
	return &cognitoidentityprovider.DeleteGroupOutput{}, nil
}

func TestEnsureGroupCreatesAndIsIdempotent(t *testing.T) {
	api := &fakeGroupAPI{}
	client := NewGroupClientWithAPI(api, "pool-1")

	created, err := client.EnsureGroup(context.Background(), "Coach", "Coach Cobranza")
	if err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	if !created {
		t.Fatal("want created=true")
	}

	created, err = client.EnsureGroup(context.Background(), "coach", "")
	if err != nil {
		t.Fatalf("EnsureGroup second: %v", err)
	}
	if created {
		t.Fatal("want created=false on GroupExists")
	}
	if api.createCalls != 2 {
		t.Fatalf("createCalls=%d want 2", api.createCalls)
	}
}

func TestEnsureGroupRejectsInvalidCode(t *testing.T) {
	client := NewGroupClientWithAPI(&fakeGroupAPI{}, "pool-1")
	_, err := client.EnsureGroup(context.Background(), "Bad-Role", "")
	if !errors.Is(err, ErrInvalidRoleCode) {
		t.Fatalf("err=%v want ErrInvalidRoleCode", err)
	}
}

func TestDeleteGroupIfEmpty(t *testing.T) {
	api := &fakeGroupAPI{groups: map[string]struct{}{"coach": {}}}
	client := NewGroupClientWithAPI(api, "pool-1")
	ok, err := client.DeleteGroupIfEmpty(context.Background(), "coach")
	if err != nil || !ok {
		t.Fatalf("DeleteGroupIfEmpty = (%v, %v)", ok, err)
	}
}
