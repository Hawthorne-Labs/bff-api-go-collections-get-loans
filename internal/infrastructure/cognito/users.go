package cognito

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/smithy-go"
)

// ProvisioningResult is the public Cognito block returned to the SPA (Python CognitoProvisioningResult).
type ProvisioningResult struct {
	Provisioned            bool    `json:"provisioned"`
	Status                 string  `json:"status"`
	TemporaryPassword      *string `json:"temporaryPassword"`
	RequiresPasswordChange bool    `json:"requiresPasswordChange"`
	Group                  *string `json:"group"`
}

func (r ProvisioningResult) ToPublicMap() map[string]any {
	return map[string]any{
		"provisioned":            r.Provisioned,
		"status":                 r.Status,
		"temporaryPassword":      r.TemporaryPassword,
		"requiresPasswordChange": r.RequiresPasswordChange,
		"group":                  r.Group,
	}
}

var systemRoleGroups = map[string]struct{}{
	"agent": {}, "call_center": {}, "supervisor": {}, "manager": {}, "admin": {}, "auditor": {},
}

// UserAPI is the Cognito IdP subset for identity provisioning.
type UserAPI interface {
	AdminGetUser(ctx context.Context, params *cognitoidentityprovider.AdminGetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminGetUserOutput, error)
	AdminCreateUser(ctx context.Context, params *cognitoidentityprovider.AdminCreateUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminCreateUserOutput, error)
	AdminUpdateUserAttributes(ctx context.Context, params *cognitoidentityprovider.AdminUpdateUserAttributesInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminUpdateUserAttributesOutput, error)
	AdminDisableUser(ctx context.Context, params *cognitoidentityprovider.AdminDisableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminDisableUserOutput, error)
	AdminEnableUser(ctx context.Context, params *cognitoidentityprovider.AdminEnableUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminEnableUserOutput, error)
	AdminSetUserPassword(ctx context.Context, params *cognitoidentityprovider.AdminSetUserPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminSetUserPasswordOutput, error)
	AdminListGroupsForUser(ctx context.Context, params *cognitoidentityprovider.AdminListGroupsForUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminListGroupsForUserOutput, error)
	AdminAddUserToGroup(ctx context.Context, params *cognitoidentityprovider.AdminAddUserToGroupInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminAddUserToGroupOutput, error)
	AdminRemoveUserFromGroup(ctx context.Context, params *cognitoidentityprovider.AdminRemoveUserFromGroupInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.AdminRemoveUserFromGroupOutput, error)
	CreateGroup(ctx context.Context, params *cognitoidentityprovider.CreateGroupInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.CreateGroupOutput, error)
}

// UserClient provisions Cognito users for admin user management (Python CognitoClient).
type UserClient struct {
	client UserAPI
	poolID string
}

// NewUserClient builds a Cognito user admin client. Returns (nil, nil) when pool/region missing.
func NewUserClient(ctx context.Context, region, poolID string) (*UserClient, error) {
	region = strings.TrimSpace(region)
	poolID = strings.TrimSpace(poolID)
	if region == "" || poolID == "" {
		return nil, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(4))
	if err != nil {
		return nil, err
	}
	return &UserClient{client: cognitoidentityprovider.NewFromConfig(cfg), poolID: poolID}, nil
}

// NewUserClientWithAPI wires a fake Cognito API (tests).
func NewUserClientWithAPI(api UserAPI, poolID string) *UserClient {
	return &UserClient{client: api, poolID: strings.TrimSpace(poolID)}
}

// AdminSyncUser mirrors Python admin_sync_user.
func (c *UserClient) AdminSyncUser(ctx context.Context, email, name, role string, active bool) (ProvisioningResult, error) {
	if c == nil || c.client == nil || c.poolID == "" {
		return ProvisioningResult{}, ErrPoolNotConfigured
	}
	normalizedEmail := normalizeEmail(email)
	normalizedName := normalizeDisplayName(name)
	normalizedRole, err := NormalizeRoleCode(role)
	if err != nil || normalizedEmail == "" || normalizedName == "" {
		return ProvisioningResult{}, fmt.Errorf("invalid Cognito identity synchronization input")
	}
	group := normalizedRole

	exists, err := c.userExists(ctx, normalizedEmail)
	if err != nil {
		return ProvisioningResult{}, err
	}
	if !exists && !active {
		return ProvisioningResult{Provisioned: false, Status: "absent_disabled", Group: &group}, nil
	}
	if !active && exists {
		suffixed := deactivatedUsername(normalizedEmail)
		if _, err := c.client.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
			UserPoolId: aws.String(c.poolID),
			Username:   aws.String(normalizedEmail),
			UserAttributes: []types.AttributeType{
				{Name: aws.String("email"), Value: aws.String(suffixed)},
				{Name: aws.String("email_verified"), Value: aws.String("true")},
			},
		}); err != nil {
			return ProvisioningResult{}, err
		}
		if _, err := c.client.AdminDisableUser(ctx, &cognitoidentityprovider.AdminDisableUserInput{
			UserPoolId: aws.String(c.poolID),
			Username:   aws.String(suffixed),
		}); err != nil {
			return ProvisioningResult{}, err
		}
		return ProvisioningResult{Provisioned: true, Status: "disabled", Group: &group}, nil
	}

	var temporaryPassword *string
	created := false
	if !exists {
		pwd, wasCreated, createErr := c.adminCreateUser(ctx, normalizedEmail, normalizedName, normalizedRole)
		if createErr != nil {
			return ProvisioningResult{}, createErr
		}
		created = wasCreated
		if pwd != "" {
			temporaryPassword = &pwd
		}
	}

	if _, err := c.client.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId:     aws.String(c.poolID),
		Username:       aws.String(normalizedEmail),
		UserAttributes: identityAttributes(normalizedEmail, normalizedName, normalizedRole),
	}); err != nil {
		return ProvisioningResult{}, err
	}
	if err := c.reconcileRoleGroup(ctx, normalizedEmail, normalizedRole); err != nil {
		return ProvisioningResult{}, err
	}
	if _, err := c.client.AdminEnableUser(ctx, &cognitoidentityprovider.AdminEnableUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(normalizedEmail),
	}); err != nil {
		return ProvisioningResult{}, err
	}

	status := "updated"
	if created {
		status = "created"
	}
	return ProvisioningResult{
		Provisioned:            true,
		Status:                 status,
		TemporaryPassword:      temporaryPassword,
		RequiresPasswordChange: created,
		Group:                  &group,
	}, nil
}

// AdminResetOrSyncUser mirrors Python admin_reset_or_sync_user (BUG-0588).
func (c *UserClient) AdminResetOrSyncUser(ctx context.Context, email, name, role string, active bool) (ProvisioningResult, error) {
	result, err := c.setTemporaryPassword(ctx, email)
	if err == nil {
		return result, nil
	}
	if !isUserNotFound(err) {
		return ProvisioningResult{}, err
	}
	synchronized, syncErr := c.AdminSyncUser(ctx, email, name, role, active)
	if syncErr != nil {
		return ProvisioningResult{}, syncErr
	}
	if synchronized.TemporaryPassword == nil {
		return synchronized, nil
	}
	synchronized.Status = "password_reset"
	return synchronized, nil
}

func (c *UserClient) setTemporaryPassword(ctx context.Context, email string) (ProvisioningResult, error) {
	if c == nil || c.client == nil || c.poolID == "" {
		return ProvisioningResult{}, ErrPoolNotConfigured
	}
	normalizedEmail := normalizeEmail(email)
	if normalizedEmail == "" {
		return ProvisioningResult{}, fmt.Errorf("invalid email")
	}
	pwd := generateTempPassword()
	if _, err := c.client.AdminSetUserPassword(ctx, &cognitoidentityprovider.AdminSetUserPasswordInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(normalizedEmail),
		Password:   aws.String(pwd),
		Permanent:  false,
	}); err != nil {
		return ProvisioningResult{}, err
	}
	return ProvisioningResult{
		Provisioned:            true,
		Status:                 "password_reset",
		TemporaryPassword:      &pwd,
		RequiresPasswordChange: true,
	}, nil
}

func (c *UserClient) userExists(ctx context.Context, email string) (bool, error) {
	_, err := c.client.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(email),
	})
	if err == nil {
		return true, nil
	}
	if isUserNotFound(err) {
		return false, nil
	}
	return false, err
}

func (c *UserClient) adminCreateUser(ctx context.Context, email, name, role string) (string, bool, error) {
	pwd := generateTempPassword()
	_, err := c.client.AdminCreateUser(ctx, &cognitoidentityprovider.AdminCreateUserInput{
		UserPoolId:        aws.String(c.poolID),
		Username:          aws.String(email),
		UserAttributes:    identityAttributes(email, name, role),
		TemporaryPassword: aws.String(pwd),
		MessageAction:     types.MessageActionTypeSuppress,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "UsernameExistsException" {
			return "", false, nil
		}
		return "", false, err
	}
	return pwd, true, nil
}

func (c *UserClient) reconcileRoleGroup(ctx context.Context, email, role string) error {
	if _, err := c.client.CreateGroup(ctx, &cognitoidentityprovider.CreateGroupInput{
		GroupName:  aws.String(role),
		UserPoolId: aws.String(c.poolID),
	}); err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "GroupExistsException" {
			return err
		}
	}
	listed, err := c.client.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(email),
	})
	if err != nil {
		return err
	}
	groups := map[string]struct{}{}
	for _, g := range listed.Groups {
		name := strings.ToLower(strings.TrimSpace(aws.ToString(g.GroupName)))
		if name != "" {
			groups[name] = struct{}{}
		}
	}
	removable := map[string]struct{}{}
	for g := range groups {
		if _, ok := systemRoleGroups[g]; ok {
			removable[g] = struct{}{}
		}
		if _, err := NormalizeRoleCode(g); err == nil {
			removable[g] = struct{}{}
		}
	}
	for g := range removable {
		if g == role {
			continue
		}
		if _, err := c.client.AdminRemoveUserFromGroup(ctx, &cognitoidentityprovider.AdminRemoveUserFromGroupInput{
			UserPoolId: aws.String(c.poolID),
			Username:   aws.String(email),
			GroupName:  aws.String(g),
		}); err != nil {
			log.Printf("cognito remove group skipped group=%s err=%v", g, err)
		}
	}
	if _, ok := groups[role]; ok {
		return nil
	}
	_, err = c.client.AdminAddUserToGroup(ctx, &cognitoidentityprovider.AdminAddUserToGroupInput{
		UserPoolId: aws.String(c.poolID),
		Username:   aws.String(email),
		GroupName:  aws.String(role),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceNotFoundException" {
			// anti-regresion: BUG-0925
			log.Printf("cognito role group missing role=%s", role)
			return nil
		}
		return err
	}
	return nil
}

func identityAttributes(email, name, role string) []types.AttributeType {
	return []types.AttributeType{
		{Name: aws.String("email"), Value: aws.String(email)},
		{Name: aws.String("email_verified"), Value: aws.String("true")},
		{Name: aws.String("name"), Value: aws.String(name)},
		{Name: aws.String("custom:role"), Value: aws.String(role)},
	}
}

func normalizeEmail(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) > 254 || strings.Count(normalized, "@") != 1 {
		return ""
	}
	for _, r := range normalized {
		if unicode.IsSpace(r) {
			return ""
		}
	}
	local, domain, ok := strings.Cut(normalized, "@")
	if !ok || local == "" || domain == "" || !strings.Contains(domain, ".") {
		return ""
	}
	return normalized
}

func normalizeDisplayName(value string) string {
	parts := strings.Fields(value)
	joined := strings.Join(parts, " ")
	if len(joined) > 256 {
		return joined[:256]
	}
	return joined
}

func deactivatedUsername(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok {
		return fmt.Sprintf("%s_DEACTIVATED_%d", email, time.Now().Unix())
	}
	return fmt.Sprintf("%s+DEACTIVATED_%d@%s", local, time.Now().Unix(), domain)
}

func generateTempPassword() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	for {
		buf := make([]byte, 14)
		for i := range buf {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			buf[i] = alphabet[n.Int64()]
		}
		pwd := string(buf)
		var lower, upper, digit, special bool
		for _, c := range pwd {
			switch {
			case c >= 'a' && c <= 'z':
				lower = true
			case c >= 'A' && c <= 'Z':
				upper = true
			case c >= '0' && c <= '9':
				digit = true
			default:
				special = true
			}
		}
		if lower && upper && digit && special {
			return pwd
		}
	}
}

func isUserNotFound(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "UserNotFoundException"
}
