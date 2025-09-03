// Package config provides environment-based configuration for GCP bootstrap infrastructure
package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/davidmontoyago/pulumi-gcp-bootstrap/pkg/bootstrap/gcp"
	"github.com/kelseyhightower/envconfig"
)

// Config holds all the configuration from environment variables
type Config struct {
	// GCP project to bootstrap. Required.
	Project string `envconfig:"PROJECT" required:"true"`
	// GCP region to bootstrap. Required.
	Region string `envconfig:"REGION" default:"us-central1"`

	// Period of time to rotate the KMS key for the state bucket
	StateBucketKeyRotationPeriod string `envconfig:"STATE_BUCKET_KEY_ROTATION_PERIOD" default:"2592000s"`
	// Number of days to retain archived objects in the infra state bucket
	StateBucketArchivedObjectsRetentionDays int `envconfig:"STATE_BUCKET_ARCHIVED_OBJECTS_RETENTION_DAYS" default:"365"`

	// Project to which audit and security logs will be exported
	LoggingDestinationProject string `envconfig:"LOGGING_DESTINATION_PROJECT" default:""`
	// Number of days to retain audit and security logs. Defaults to 365 days.
	LoggingRetentionDays int `envconfig:"LOGGING_RETENTION_DAYS" default:"365"`

	// List of member groups are allowed to administer the infrastructure
	AdminMembers string `envconfig:"ADMIN_MEMBERS" default:""`
	// List of member groups are allowed to audit the infrastructure as security admins
	SecurityMembers string `envconfig:"SECURITY_MEMBERS" default:""`

	// Labels to be applied to the resources (comma-separated key=value pairs)
	Labels string `envconfig:"LABELS" default:""`
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
		config.LoggingDestinationProject = config.Project
	}

	log.Printf("Configuration loaded successfully:")
	log.Printf("  Project: %s", config.Project)
	log.Printf("  Region: %s", config.Region)
	log.Printf("  State Bucket Key Rotation Period: %s", config.StateBucketKeyRotationPeriod)
	log.Printf("  State Bucket Archived Objects Retention Days: %d", config.StateBucketArchivedObjectsRetentionDays)
	log.Printf("  Logging Destination Project: %s", config.LoggingDestinationProject)
	log.Printf("  Logging Retention Days: %d", config.LoggingRetentionDays)
	log.Printf("  Admin Members: %s", config.AdminMembers)
	log.Printf("  Security Members: %s", config.SecurityMembers)
	log.Printf("  Labels: %s", config.Labels)

	return &config, nil
}

// ToBootstrapArgs converts the config to BootstrapArgs for use with the Pulumi component
func (c *Config) ToBootstrapArgs() *gcp.BootstrapArgs {
	args := &gcp.BootstrapArgs{
		Project:                                 c.Project,
		Region:                                  c.Region,
		StateBucketKeyRotationPeriod:            c.StateBucketKeyRotationPeriod,
		StateBucketArchivedObjectsRetentionDays: c.StateBucketArchivedObjectsRetentionDays,
		LoggingDestinationProject:               c.LoggingDestinationProject,
		LoggingRetentionDays:                    c.LoggingRetentionDays,
	}

	// Parse comma-separated member lists
	if c.AdminMembers != "" {
		args.AdminMembers = strings.Split(strings.TrimSpace(c.AdminMembers), ",")
		for i := range args.AdminMembers {
			args.AdminMembers[i] = strings.TrimSpace(args.AdminMembers[i])
		}
	}

	if c.SecurityMembers != "" {
		args.SecurityMembers = strings.Split(strings.TrimSpace(c.SecurityMembers), ",")
		for i := range args.SecurityMembers {
			args.SecurityMembers[i] = strings.TrimSpace(args.SecurityMembers[i])
		}
	}

	// Parse comma-separated key=value labels
	if c.Labels != "" {
		args.Labels = make(map[string]string)
		labelPairs := strings.Split(c.Labels, ",")
		for _, pair := range labelPairs {
			kv := strings.Split(strings.TrimSpace(pair), "=")
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				args.Labels[key] = value
			}
		}
	}

	return args
}
