package cognito

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/smithy-go"
)

var roleCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ErrPoolNotConfigured is returned when Cognito user pool id is missing.
var ErrPoolNotConfigured = errors.New("cognito user pool is not configured")

// ErrInvalidRoleCode is returned when the group name fails validation.
var ErrInvalidRoleCode = errors.New("invalid Cognito group name")

// GroupAPI is the Cognito IdP subset used for role-group provisioning.
type GroupAPI interface {
	CreateGroup(ctx context.Context, params *cognitoidentityprovider.CreateGroupInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.CreateGroupOutput, error)
	DeleteGroup(ctx context.Context, params *cognitoidentityprovider.DeleteGroupInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DeleteGroupOutput, error)
}

// GroupClient provisions Cognito groups matching identity.roles.code.
type GroupClient struct {
	client GroupAPI
	poolID string
}

// NewGroupClient builds a Cognito group client from region + pool id.
// Returns (nil, nil) when region or pool id is empty.
func NewGroupClient(ctx context.Context, region, poolID string) (*GroupClient, error) {
	region = strings.TrimSpace(region)
	poolID = strings.TrimSpace(poolID)
	if region == "" || poolID == "" {
		return nil, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(4))
	if err != nil {
		return nil, err
	}
	return &GroupClient{
		client: cognitoidentityprovider.NewFromConfig(cfg),
		poolID: poolID,
	}, nil
}

// NewGroupClientWithAPI wires a fake or custom Cognito IdP client (tests).
func NewGroupClientWithAPI(api GroupAPI, poolID string) *GroupClient {
	return &GroupClient{client: api, poolID: strings.TrimSpace(poolID)}
}

// EnsureGroup creates the Cognito group if missing. Returns true when created.
func (c *GroupClient) EnsureGroup(ctx context.Context, code, description string) (bool, error) {
	if c == nil || c.client == nil || c.poolID == "" {
		return false, ErrPoolNotConfigured
	}
	normalized, err := NormalizeRoleCode(code)
	if err != nil {
		return false, err
	}
	input := &cognitoidentityprovider.CreateGroupInput{
		GroupName:  aws.String(normalized),
		UserPoolId: aws.String(c.poolID),
	}
	if desc := strings.TrimSpace(description); desc != "" {
		if len(desc) > 2048 {
			desc = desc[:2048]
		}
		input.Description = aws.String(desc)
	}
	_, err = c.client.CreateGroup(ctx, input)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "GroupExistsException" {
			return false, nil
		}
		return false, err
	}
	log.Printf("cognito role group created role_code=%s", normalized)
	return true, nil
}

// DeleteGroupIfEmpty compensates an orphan CreateGroup (best-effort).
func (c *GroupClient) DeleteGroupIfEmpty(ctx context.Context, code string) (bool, error) {
	if c == nil || c.client == nil || c.poolID == "" {
		return false, nil
	}
	normalized, err := NormalizeRoleCode(code)
	if err != nil {
		return false, nil
	}
	_, err = c.client.DeleteGroup(ctx, &cognitoidentityprovider.DeleteGroupInput{
		GroupName:  aws.String(normalized),
		UserPoolId: aws.String(c.poolID),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "ResourceNotFoundException", "InvalidParameterException":
				return false, nil
			}
			log.Printf("cognito group compensation delete skipped role_code=%s error_type=%s", normalized, apiErr.ErrorCode())
			return false, nil
		}
		return false, err
	}
	log.Printf("cognito role group deleted (compensation) role_code=%s", normalized)
	return true, nil
}

// NormalizeRoleCode lowercases and validates ^[a-z][a-z0-9_]*$ (max 64).
func NormalizeRoleCode(code string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if normalized == "" || len(normalized) > 64 || !roleCodeRE.MatchString(normalized) {
		return "", fmt.Errorf("%w: %q", ErrInvalidRoleCode, code)
	}
	return normalized, nil
}
