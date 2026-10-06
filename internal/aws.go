package internal

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// NewConfig creates a config for accessing AWS with passing credential parameters.
func NewConfig(ctx context.Context, key, secret, session, region, roleArn string) (aws.Config, error) {
	var (
		opts []func(*config.LoadOptions) error
		cfg  aws.Config
		err  error
	)
	if ctx == nil {
		return aws.Config{}, WrapError(ErrInvalidParams)
	}

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	// if parameters for credentials doesn't pass it.
	if key == "" || secret == "" {
		cfg, err = config.LoadDefaultConfig(ctx, opts...)
	} else {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(key, secret, session)))
		cfg, err = config.LoadDefaultConfig(ctx, opts...)
	}
	if err != nil {
		return aws.Config{}, WrapError(err)
	}

	// https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/stscreds
	if roleArn != "" {
		sts := sts.NewFromConfig(cfg)
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts, roleArn))
	}

	return cfg, nil
}

// NewSharedConfig creates a config for accessing AWS that is based on shared files, such as credentials file.
func NewSharedConfig(ctx context.Context, profile string, sharedConfigFiles, sharedCredentialsFiles []string) (aws.Config, error) {
	if ctx == nil {
		return aws.Config{}, WrapError(ErrInvalidParams)
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(profile),
		config.WithSharedConfigFiles(sharedConfigFiles),
		config.WithSharedCredentialsFiles(sharedCredentialsFiles),
	)
	if err != nil {
		return aws.Config{}, WrapError(err)
	}

	return cfg, nil
}

// IsSSOProfile reports whether the profile in shared config uses AWS IAM Identity Center (SSO).
func IsSSOProfile(ctx context.Context, profile string) bool {
	sc, err := config.LoadSharedConfigProfile(ctx, profile)
	if err != nil {
		return false
	}
	return sc.SSOSession != nil || sc.SSOSessionName != "" || sc.SSOStartURL != ""
}

// SSOErrorHint returns a hint for credential errors from SSO profile.
func SSOErrorHint(err error, profile string) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ForbiddenException" {
		return fmt.Sprintf("no access to the role of profile %s, check sso_account_id / sso_role_name or your permission set assignment", profile)
	}
	return fmt.Sprintf("login required or token expired, run `aws sso login --profile %s`", profile)
}
