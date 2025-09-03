// Package config provides environment-based configuration for GCP bootstrap infrastructure
package config

import (
	"fmt"
	"log"

	"github.com/kelseyhightower/envconfig"
)

// Config holds all the configuration from environment variables
type Config struct {
	// GCP Project ID where resources will be created
	GCPProject string `envconfig:"GCP_PROJECT" required:"true"`
	// GCP Region for regional resources
	GCPRegion string `envconfig:"GCP_REGION" default:"us-central1"`
	// KMS key rotation period in seconds (default: 30 days)
	KMSKeyRotationPeriod string `envconfig:"KMS_KEY_ROTATION_PERIOD" default:"2592000s"`
	// State bucket prefix for naming
	StateStoragePrefix string `envconfig:"STATE_STORAGE_PREFIX" default:"infra-state"`
	// Bucket retention period in days
	RetentionPeriodDays int `envconfig:"RETENTION_PERIOD_DAYS" default:"365"`
	// Enable uniform bucket-level access
	UniformBucketLevelAccess bool `envconfig:"UNIFORM_BUCKET_LEVEL_ACCESS" default:"true"`
	// Enable public access prevention
	PublicAccessPrevention string `envconfig:"PUBLIC_ACCESS_PREVENTION" default:"enforced"`
	// Logging sink destination project (defaults to same as GCP_PROJECT)
	LoggingDestinationProject string `envconfig:"LOGGING_DESTINATION_PROJECT" default:""`
	// Logging retention days
	LoggingRetentionDays int `envconfig:"LOGGING_RETENTION_DAYS" default:"30"`
	// Environment for labeling
	Environment string `envconfig:"ENVIRONMENT" default:"production"`
	// Organization domain for policies
	OrgDomain string `envconfig:"ORG_DOMAIN" default:"example.com"`
	// Enable organization policies
	EnableOrgPolicies bool `envconfig:"ENABLE_ORG_POLICIES" default:"true"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	var config Config

	err := envconfig.Process("", &config)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration from environment variables: %w", err)
	}

	// Set default logging destination project if not specified
	if config.LoggingDestinationProject == "" {
		config.LoggingDestinationProject = config.GCPProject
	}

	log.Printf("Configuration loaded successfully:")
	log.Printf("  GCP Project: %s", config.GCPProject)
	log.Printf("  GCP Region: %s", config.GCPRegion)
	log.Printf("  State Storage Prefix: %s", config.StateStoragePrefix)
	log.Printf("  KMS Key Rotation Period: %s", config.KMSKeyRotationPeriod)
	log.Printf("  Retention Period Days: %d", config.RetentionPeriodDays)
	log.Printf("  Uniform Bucket Level Access: %t", config.UniformBucketLevelAccess)
	log.Printf("  Public Access Prevention: %s", config.PublicAccessPrevention)
	log.Printf("  Logging Destination Project: %s", config.LoggingDestinationProject)
	log.Printf("  Logging Retention Days: %d", config.LoggingRetentionDays)
	log.Printf("  Environment: %s", config.Environment)
	log.Printf("  Organization Domain: %s", config.OrgDomain)
	log.Printf("  Enable Organization Policies: %t", config.EnableOrgPolicies)

	return &config, nil
}
