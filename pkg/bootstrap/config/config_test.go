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
				"GCP_PROJECT": "test-project",
				"GCP_REGION":  "us-central1",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "test-project", cfg.GCPProject)
				assert.Equal(t, "us-central1", cfg.GCPRegion)
				assert.Equal(t, "2592000s", cfg.KMSKeyRotationPeriod)
				assert.Equal(t, "infra-state", cfg.StateStoragePrefix)
				assert.Equal(t, 365, cfg.RetentionPeriodDays)
				assert.True(t, cfg.UniformBucketLevelAccess)
				assert.Equal(t, "enforced", cfg.PublicAccessPrevention)
				assert.Equal(t, "test-project", cfg.LoggingDestinationProject)
				assert.Equal(t, 30, cfg.LoggingRetentionDays)
				assert.Equal(t, "production", cfg.Environment)
			},
		},
		{
			name: "configuration with custom values",
			envVars: map[string]string{
				"GCP_PROJECT":                 "custom-project",
				"GCP_REGION":                  "europe-west1",
				"KMS_KEY_ROTATION_PERIOD":     "7776000s",
				"STATE_STORAGE_PREFIX":        "custom-state",
				"RETENTION_PERIOD_DAYS":       "730",
				"UNIFORM_BUCKET_LEVEL_ACCESS": "false",
				"PUBLIC_ACCESS_PREVENTION":    "inherited",
				"LOGGING_DESTINATION_PROJECT": "logging-project",
				"LOGGING_RETENTION_DAYS":      "90",
				"ENVIRONMENT":                 "staging",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "custom-project", cfg.GCPProject)
				assert.Equal(t, "europe-west1", cfg.GCPRegion)
				assert.Equal(t, "7776000s", cfg.KMSKeyRotationPeriod)
				assert.Equal(t, "custom-state", cfg.StateStoragePrefix)
				assert.Equal(t, 730, cfg.RetentionPeriodDays)
				assert.False(t, cfg.UniformBucketLevelAccess)
				assert.Equal(t, "inherited", cfg.PublicAccessPrevention)
				assert.Equal(t, "logging-project", cfg.LoggingDestinationProject)
				assert.Equal(t, 90, cfg.LoggingRetentionDays)
				assert.Equal(t, "staging", cfg.Environment)
			},
		},
		{
			name:        "missing required GCP_PROJECT",
			envVars:     map[string]string{},
			expectError: true,
		},
		{
			name: "default values when optional fields not set",
			envVars: map[string]string{
				"GCP_PROJECT": "default-test-project",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "default-test-project", cfg.GCPProject)
				assert.Equal(t, "us-central1", cfg.GCPRegion)
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
		"GCP_PROJECT",
		"GCP_REGION",
		"KMS_KEY_ROTATION_PERIOD",
		"STATE_STORAGE_PREFIX",
		"RETENTION_PERIOD_DAYS",
		"UNIFORM_BUCKET_LEVEL_ACCESS",
		"PUBLIC_ACCESS_PREVENTION",
		"LOGGING_DESTINATION_PROJECT",
		"LOGGING_RETENTION_DAYS",
		"ENVIRONMENT",
	}

	for _, envVar := range envVars {
		err := os.Unsetenv(envVar)
		require.NoError(t, err)
	}
}
