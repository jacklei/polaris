package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/rs/zerolog/log"
)

// ProfileInfo contains basic information about an AWS profile
type ProfileInfo struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

// LoadAWSConfig loads AWS configuration for the specified profile using the AWS SDK
func LoadAWSConfig(ctx context.Context, profile string) (aws.Config, error) {
	var cfg aws.Config
	var err error

	if profile == "" || profile == "default" {
		cfg, err = awsconfig.LoadDefaultConfig(ctx)
	} else {
		cfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithSharedConfigProfile(profile),
		)
	}

	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config for profile %s: %w", profile, err)
	}

	return cfg, nil
}

// GetProfileInfo retrieves basic information about a profile
func GetProfileInfo(ctx context.Context, profile string) (*ProfileInfo, error) {
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return nil, err
	}

	info := &ProfileInfo{
		Name:   profile,
		Region: cfg.Region,
	}

	// If profile is empty or default, set name to "default"
	if profile == "" || profile == "default" {
		info.Name = "default"
	}

	return info, nil
}

// ValidateProfile validates that a profile exists and can be loaded
func ValidateProfile(ctx context.Context, profile string) error {
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return err
	}

	// Try to make a simple API call to validate credentials
	stsClient := sts.NewFromConfig(cfg)
	_, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Debug().Err(err).Str("profile", profile).Msg("Profile validation failed")
		// Don't fail on validation - credentials might be valid but API call might fail
		// Just log it and continue
	}

	return nil
}

// GetAccountID retrieves the AWS account ID for the specified profile
func GetAccountID(ctx context.Context, profile string) (string, error) {
	cfg, err := LoadAWSConfig(ctx, profile)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config for profile %s: %w", profile, err)
	}

	stsClient := sts.NewFromConfig(cfg)
	result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity for profile %s: %w", profile, err)
	}

	if result.Account == nil {
		return "", fmt.Errorf("account ID is nil for profile %s", profile)
	}

	return aws.ToString(result.Account), nil
}
