package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	// Test cases
	tests := []struct {
		name        string
		envVars     map[string]string
		expectError bool
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid configuration with required fields",
			envVars: map[string]string{
				"PROJECT": "test-project",
				"REGION":  "us-central1",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "test-project", cfg.Project)
				assert.Equal(t, "us-central1", cfg.Region)
				assert.Equal(t, "2592000s", cfg.StateBucketKeyRotationPeriod)
				assert.Equal(t, 365, cfg.StateBucketArchivedObjectsRetentionDays)
				assert.Equal(t, "test-project", cfg.LoggingDestinationProject)
				assert.Equal(t, 365, cfg.LoggingRetentionDays)
				assert.Equal(t, "", cfg.AdminMembers)
				assert.Equal(t, "", cfg.SecurityMembers)
				assert.Equal(t, "", cfg.Labels)
			},
		},
		{
			name: "configuration with custom values",
			envVars: map[string]string{
				"PROJECT":                          "custom-project",
				"REGION":                           "europe-west1",
				"STATE_BUCKET_KEY_ROTATION_PERIOD": "7776000s",
				"STATE_BUCKET_ARCHIVED_OBJECTS_RETENTION_DAYS": "730",
				"LOGGING_DESTINATION_PROJECT":                  "logging-project",
				"LOGGING_RETENTION_DAYS":                       "90",
				"ADMIN_MEMBERS":                                "group:admin@example.com,user:admin@example.com",
				"SECURITY_MEMBERS":                             "group:security@example.com",
				"LABELS":                                       "environment=staging,team=platform",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "custom-project", cfg.Project)
				assert.Equal(t, "europe-west1", cfg.Region)
				assert.Equal(t, "7776000s", cfg.StateBucketKeyRotationPeriod)
				assert.Equal(t, 730, cfg.StateBucketArchivedObjectsRetentionDays)
				assert.Equal(t, "logging-project", cfg.LoggingDestinationProject)
				assert.Equal(t, 90, cfg.LoggingRetentionDays)
				assert.Equal(t, "group:admin@example.com,user:admin@example.com", cfg.AdminMembers)
				assert.Equal(t, "group:security@example.com", cfg.SecurityMembers)
				assert.Equal(t, "environment=staging,team=platform", cfg.Labels)
			},
		},
		{
			name:        "missing required PROJECT",
			envVars:     map[string]string{},
			expectError: true,
		},
		{
			name: "default values when optional fields not set",
			envVars: map[string]string{
				"PROJECT": "default-test-project",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "default-test-project", cfg.Project)
				assert.Equal(t, "us-central1", cfg.Region)
				assert.Equal(t, "default-test-project", cfg.LoggingDestinationProject)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			clearEnvVars(t)

			// Set test environment variables
			for key, value := range tt.envVars {
				err := os.Setenv(key, value)
				require.NoError(t, err)
			}

			// Test LoadConfig
			cfg, err := LoadConfig()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}

			// Cleanup
			clearEnvVars(t)
		})
	}
}

func clearEnvVars(t *testing.T) {
	envVars := []string{
		"PROJECT",
		"REGION",
		"STATE_BUCKET_KEY_ROTATION_PERIOD",
		"STATE_BUCKET_ARCHIVED_OBJECTS_RETENTION_DAYS",
		"LOGGING_DESTINATION_PROJECT",
		"LOGGING_RETENTION_DAYS",
		"ADMIN_MEMBERS",
		"SECURITY_MEMBERS",
		"LABELS",
	}

	for _, envVar := range envVars {
		err := os.Unsetenv(envVar)
		require.NoError(t, err)
	}
}

func TestConfig_ToBootstrapArgs(t *testing.T) {
	cfg := &Config{
		Project:                                 "test-project",
		Region:                                  "us-west2",
		StateBucketKeyRotationPeriod:            "7776000s",
		StateBucketArchivedObjectsRetentionDays: 730,
		LoggingDestinationProject:               "logging-project",
		LoggingRetentionDays:                    90,
		AdminMembers:                            "group:admin@example.com,user:admin@example.com",
		SecurityMembers:                         "group:security@example.com",
		Labels:                                  "environment=staging,team=platform",
	}

	args := cfg.ToBootstrapArgs()

	// Test basic fields
	assert.Equal(t, "test-project", args.Project)
	assert.Equal(t, "us-west2", args.Region)
	assert.Equal(t, "7776000s", args.StateBucketKeyRotationPeriod)
	assert.Equal(t, 730, args.StateBucketArchivedObjectsRetentionDays)
	assert.Equal(t, "logging-project", args.LoggingDestinationProject)
	assert.Equal(t, 90, args.LoggingRetentionDays)

	// Test parsed member lists
	assert.Equal(t, []string{"group:admin@example.com", "user:admin@example.com"}, args.AdminMembers)
	assert.Equal(t, []string{"group:security@example.com"}, args.SecurityMembers)

	// Test parsed labels
	expectedLabels := map[string]string{
		"environment": "staging",
		"team":        "platform",
	}
	assert.Equal(t, expectedLabels, args.Labels)
}

func TestConfig_ToBootstrapArgs_EmptyValues(t *testing.T) {
	cfg := &Config{
		Project: "test-project",
		Region:  "us-central1",
	}

	args := cfg.ToBootstrapArgs()

	assert.Equal(t, "test-project", args.Project)
	assert.Equal(t, "us-central1", args.Region)
	assert.Nil(t, args.AdminMembers)
	assert.Nil(t, args.SecurityMembers)
	assert.Nil(t, args.Labels)
}
