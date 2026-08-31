package cognito

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type fakeUserAPI struct {
	getByAlias map[string]*cognitoidentityprovider.AdminGetUserOutput
	disableUsernames []string
	enableUsernames  []string
	updateUsernames  []string
	setPasswordUsernames []string
	groups           map[string][]string
}

func (f *fakeUserAPI) AdminGetUser(_ context.Context, params *cognitoidentityprovider.AdminGetUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error) {
	key := aws.ToString(params.Username)
	if out, ok := f.getByAlias[key]; ok {
		return out, nil
	}
	return nil, &types.UserNotFoundException{Message: aws.String("not found")}
}

func (f *fakeUserAPI) AdminCreateUser(context.Context, *cognitoidentityprovider.AdminCreateUserInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error) {
	return &cognitoidentityprovider.AdminCreateUserOutput{}, nil
}

func (f *fakeUserAPI) AdminUpdateUserAttributes(_ context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error) {
	f.updateUsernames = append(f.updateUsernames, aws.ToString(params.Username))
	return &cognitoidentityprovider.AdminUpdateUserAttributesOutput{}, nil
}

func (f *fakeUserAPI) AdminDisableUser(_ context.Context, params *cognitoidentityprovider.AdminDisableUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error) {
	f.disableUsernames = append(f.disableUsernames, aws.ToString(params.Username))
	return &cognitoidentityprovider.AdminDisableUserOutput{}, nil
}

func (f *fakeUserAPI) AdminEnableUser(_ context.Context, params *cognitoidentityprovider.AdminEnableUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error) {
	f.enableUsernames = append(f.enableUsernames, aws.ToString(params.Username))
	return &cognitoidentityprovider.AdminEnableUserOutput{}, nil
}

func (f *fakeUserAPI) AdminSetUserPassword(_ context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error) {
	f.setPasswordUsernames = append(f.setPasswordUsernames, aws.ToString(params.Username))
	return &cognitoidentityprovider.AdminSetUserPasswordOutput{}, nil
}

func (f *fakeUserAPI) AdminListGroupsForUser(_ context.Context, params *cognitoidentityprovider.AdminListGroupsForUserInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminListGroupsForUserOutput, error) {
	name := aws.ToString(params.Username)
	var groups []types.GroupType
	for _, g := range f.groups[name] {
		groups = append(groups, types.GroupType{GroupName: aws.String(g)})
	}
	return &cognitoidentityprovider.AdminListGroupsForUserOutput{Groups: groups}, nil
}

func (f *fakeUserAPI) AdminAddUserToGroup(context.Context, *cognitoidentityprovider.AdminAddUserToGroupInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminAddUserToGroupOutput, error) {
	return &cognitoidentityprovider.AdminAddUserToGroupOutput{}, nil
}

func (f *fakeUserAPI) AdminRemoveUserFromGroup(context.Context, *cognitoidentityprovider.AdminRemoveUserFromGroupInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminRemoveUserFromGroupOutput, error) {
	return &cognitoidentityprovider.AdminRemoveUserFromGroupOutput{}, nil
}

func (f *fakeUserAPI) CreateGroup(context.Context, *cognitoidentityprovider.CreateGroupInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.CreateGroupOutput, error) {
	return &cognitoidentityprovider.CreateGroupOutput{}, nil
}

func TestAdminSyncUserDisableUsesResolvedUUIDUsername(t *testing.T) {
	const email = "jcfuentes@inversa.hn"
	const uuid = "f1bb15e0-7041-7098-e10d-4190b786edc2"
	api := &fakeUserAPI{
		getByAlias: map[string]*cognitoidentityprovider.AdminGetUserOutput{
			email: {Username: aws.String(uuid)},
		},
		groups: map[string][]string{uuid: {"admin"}},
	}
	client := NewUserClientWithAPI(api, "pool-1")

	result, err := client.AdminSyncUser(context.Background(), email, "Juan Carlos", "admin", false)
	if err != nil {
		t.Fatalf("AdminSyncUser: %v", err)
	}
	if result.Status != "disabled" {
		t.Fatalf("status=%q want disabled", result.Status)
	}
	if len(api.disableUsernames) != 1 || api.disableUsernames[0] != uuid {
		t.Fatalf("disable usernames=%v want [%s]", api.disableUsernames, uuid)
	}
	if len(api.updateUsernames) != 1 || api.updateUsernames[0] != uuid {
		t.Fatalf("update usernames=%v want [%s]", api.updateUsernames, uuid)
	}
}

func TestSetTemporaryPasswordUsesResolvedUUIDUsername(t *testing.T) {
	const email = "jcfuentes@inversa.hn"
	const uuid = "f1bb15e0-7041-7098-e10d-4190b786edc2"
	api := &fakeUserAPI{
		getByAlias: map[string]*cognitoidentityprovider.AdminGetUserOutput{
			email: {Username: aws.String(uuid)},
		},
	}
	client := NewUserClientWithAPI(api, "pool-1")

	result, err := client.setTemporaryPassword(context.Background(), email)
	if err != nil {
		t.Fatalf("setTemporaryPassword: %v", err)
	}
	if result.Status != "password_reset" {
		t.Fatalf("status=%q want password_reset", result.Status)
	}
	if len(api.setPasswordUsernames) != 1 || api.setPasswordUsernames[0] != uuid {
		t.Fatalf("setPassword usernames=%v want [%s]", api.setPasswordUsernames, uuid)
	}
}
