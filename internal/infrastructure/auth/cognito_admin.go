package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/smithy-go"
)

// EmailLookup resolves a Cognito username/sub to an email address.
type EmailLookup interface {
	LookupEmail(ctx context.Context, username string) (email string, notFound bool, err error)
}

// AWSCognitoEmailLookup uses AdminGetUser. The ECS task role already grants this for activity-log.
type AWSCognitoEmailLookup struct {
	client *cognitoidentityprovider.Client
	poolID string
}

func NewAWSCognitoEmailLookup(ctx context.Context, region, poolID string) (*AWSCognitoEmailLookup, error) {
	if strings.TrimSpace(region) == "" || strings.TrimSpace(poolID) == "" {
		return nil, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(4))
	if err != nil {
		return nil, err
	}
	return &AWSCognitoEmailLookup{
		client: cognitoidentityprovider.NewFromConfig(cfg),
		poolID: poolID,
	}, nil
}

func (l *AWSCognitoEmailLookup) LookupEmail(ctx context.Context, username string) (string, bool, error) {
	if l == nil || l.client == nil {
		return "", false, nil
	}
	out, err := l.client.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
		UserPoolId: aws.String(l.poolID),
		Username:   aws.String(username),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "UserNotFoundException" {
			return "", true, nil
		}
		return "", false, err
	}
	for _, attr := range out.UserAttributes {
		if aws.ToString(attr.Name) == "email" {
			return strings.TrimSpace(aws.ToString(attr.Value)), false, nil
		}
	}
	return "", false, nil
}
