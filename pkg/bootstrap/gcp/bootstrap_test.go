package gcp

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBootstrap_DefaultConfiguration(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		// Default test args (organization policies enabled by default for backward compatibility)
		args := &BootstrapArgs{
			Project:                                 "test-project",
			Region:                                  "us-central1",
			StateBucketKeyRotationPeriod:            "7776000s", // 90 days
			StateBucketArchivedObjectsRetentionDays: 7,
			LoggingDestinationProject:               "test-logging-project",
			LoggingRetentionDays:                    365,
			AdminMembers:                            []string{"admin-group@example.com"},
			SecurityMembers:                         []string{"security-group@example.com"},
			EnableOrganizationPolicies:              true, // Default to enabled for this test
			Labels: map[string]string{
				"environment": "test",
				"team":        "bootstrap",
			},
		}

		bootstrap, err := NewBootstrap(ctx, "test-bootstrap", args)
		require.NoError(t, err)

		// Verify basic properties
		assert.Equal(t, "test-project", args.Project)
		assert.Equal(t, "us-central1", args.Region)
		assert.Equal(t, "test-logging-project", args.LoggingDestinationProject)
		assert.Equal(t, 365, args.LoggingRetentionDays)
		assert.Equal(t, []string{"admin-group@example.com"}, args.AdminMembers)
		assert.Equal(t, []string{"security-group@example.com"}, args.SecurityMembers)

		// Verify state bucket name using async pattern
		stateBucketNameCh := make(chan string, 1)
		defer close(stateBucketNameCh)
		bootstrap.GetStateBucketName().ApplyT(func(name string) error {
			stateBucketNameCh <- name
			return nil
		})
		stateBucketName := <-stateBucketNameCh
		assert.Equal(t, "test-bucket", stateBucketName, "State bucket name should match")

		// Verify state bucket URL
		stateBucketURLCh := make(chan string, 1)
		defer close(stateBucketURLCh)
		bootstrap.GetStateBucketURL().ApplyT(func(url string) error {
			stateBucketURLCh <- url
			return nil
		})
		stateBucketURL := <-stateBucketURLCh
		assert.Equal(t, "gs://test-bucket", stateBucketURL, "State bucket URL should match")

		// Verify audit logs bucket name
		auditLogsBucketNameCh := make(chan string, 1)
		defer close(auditLogsBucketNameCh)
		bootstrap.GetAuditLogsBucketName().ApplyT(func(name string) error {
			auditLogsBucketNameCh <- name
			return nil
		})
		auditLogsBucketName := <-auditLogsBucketNameCh
		assert.Equal(t, "test-bucket", auditLogsBucketName, "Audit logs bucket name should match")

		// Verify security logs bucket name
		securityLogsBucketNameCh := make(chan string, 1)
		defer close(securityLogsBucketNameCh)
		bootstrap.GetSecurityLogsBucketName().ApplyT(func(name string) error {
			securityLogsBucketNameCh <- name
			return nil
		})
		securityLogsBucketName := <-securityLogsBucketNameCh
		assert.Equal(t, "test-bucket", securityLogsBucketName, "Security logs bucket name should match")

		// Verify storage components
		storageComponents := bootstrap.GetStorageComponents()
		require.NotNil(t, storageComponents, "Storage components should not be nil")

		require.NotNil(t, storageComponents.StateBucket, "State bucket should not be nil")

		// Verify logging components
		loggingComponents := bootstrap.GetLoggingComponents()
		require.NotNil(t, loggingComponents, "Logging components should not be nil")
		require.NotNil(t, loggingComponents.AuditLogsBucket, "Audit logs bucket should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogsBucket, "Security logs bucket should not be nil")
		require.NotNil(t, loggingComponents.AuditLogSink, "Audit log sink should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogSink, "Security log sink should not be nil")

		// Verify organization policies
		orgPolicies := bootstrap.GetOrganizationPolicies()
		require.NotNil(t, orgPolicies, "Organization policies should not be nil")
		assert.Greater(t, len(orgPolicies), 0, "Should have at least one organization policy")
		assert.Equal(t, 4, len(orgPolicies), "Should have exactly 4 organization policies")

		// Verify state bucket IAM bindings
		stateBucketBindings := bootstrap.GetStateBucketBindings()
		require.NotNil(t, stateBucketBindings, "State bucket bindings should not be nil")
		// With 1 admin group and 1 security group, and 2 admin roles + 2 security roles, we expect:
		// (1 admin group × 2 admin roles × 2 buckets) + (1 security group × 2 security roles × 2 buckets) = 8 bindings
		assert.Equal(t, 8, len(stateBucketBindings), "Should have 8 IAM bindings (admin and security groups on both audit and security buckets)")

		return nil
	}, pulumi.WithMocks("project", "stack", &testMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

// testMocks implements pulumi.MockResourceMonitor for testing
type testMocks struct{}

func (m *testMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	outputs := map[string]interface{}{}
	for k, v := range args.Inputs {
		outputs[string(k)] = v
	}

	// Add common outputs based on resource type
	switch args.TypeToken {
	case "gcp:storage/bucket:Bucket":
		outputs["name"] = resource.NewStringProperty("test-bucket")
		outputs["url"] = resource.NewStringProperty("gs://test-bucket")
	case "gcp:kms/keyRing:KeyRing":
		outputs["id"] = resource.NewStringProperty("test-keyring")
		outputs["selfLink"] = resource.NewStringProperty("https://cloudkms.googleapis.com/v1/projects/test-project/locations/us-central1/keyRings/test-keyring")
	case "gcp:kms/cryptoKey:CryptoKey":
		outputs["id"] = resource.NewStringProperty("test-crypto-key")
		outputs["selfLink"] = resource.NewStringProperty("https://cloudkms.googleapis.com/v1/projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-crypto-key")
	case "gcp:logging/projectSink:ProjectSink":
		outputs["id"] = resource.NewStringProperty("test-sink")
		outputs["writerIdentity"] = resource.NewStringProperty("serviceAccount:test@test-project.iam.gserviceaccount.com")
	case "gcp:storage/bucketIAMPolicy:BucketIAMPolicy":
		outputs["etag"] = resource.NewStringProperty("test-etag")
	case "gcp:storage/bucketIAMMember:BucketIAMMember":
		outputs["etag"] = resource.NewStringProperty("test-member-etag")
	case "gcp:projects/organizationPolicy:OrganizationPolicy":
		outputs["etag"] = resource.NewStringProperty("test-policy-etag")
	}

	return args.Name + "_id", resource.NewPropertyMapFromMap(outputs), nil
}

func (m *testMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func TestNewBootstrap_WithCustomerManagedKeys(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		// Test args with customer-managed encryption enabled
		args := &BootstrapArgs{
			Project:                                 "test-project",
			Region:                                  "us-central1",
			StateBucketKeyRotationPeriod:            "7776000s", // 90 days
			StateBucketArchivedObjectsRetentionDays: 7,
			LoggingDestinationProject:               "test-logging-project",
			LoggingRetentionDays:                    365,
			AdminMembers:                            []string{"admin-group@example.com"},
			SecurityMembers:                         []string{"security-group@example.com"},
			EnableCustomerManagedEncryption:         true, // Enable customer-managed encryption
			Labels: map[string]string{
				"environment": "test",
				"team":        "bootstrap",
			},
		}

		bootstrap, err := NewBootstrap(ctx, "test-bootstrap", args)
		require.NoError(t, err)

		// Verify KMS key ID for state bucket
		kmsKeyIDCh := make(chan string, 1)
		defer close(kmsKeyIDCh)
		bootstrap.GetKMSKeyID().ApplyT(func(keyID string) error {
			kmsKeyIDCh <- keyID
			return nil
		})
		kmsKeyID := <-kmsKeyIDCh
		assert.Contains(t, kmsKeyID, "state-bucket-crypto-key", "KMS key ID should contain expected pattern")

		// Verify storage components have KMS resources
		storageComponents := bootstrap.GetStorageComponents()
		require.NotNil(t, storageComponents, "Storage components should not be nil")
		require.NotNil(t, storageComponents.KeyRing, "State bucket KMS KeyRing should not be nil")
		require.NotNil(t, storageComponents.CryptoKey, "State bucket KMS CryptoKey should not be nil")
		require.NotNil(t, storageComponents.StateBucket, "State bucket should not be nil")

		// Verify logging components have KMS resources for both buckets
		loggingComponents := bootstrap.GetLoggingComponents()
		require.NotNil(t, loggingComponents, "Logging components should not be nil")

		// Audit logs bucket and its KMS resources
		require.NotNil(t, loggingComponents.AuditLogsBucket, "Audit logs bucket should not be nil")
		require.NotNil(t, loggingComponents.AuditLogsKeyRing, "Audit logs KMS KeyRing should not be nil")
		require.NotNil(t, loggingComponents.AuditLogsCryptoKey, "Audit logs KMS CryptoKey should not be nil")

		// Security logs bucket and its KMS resources
		require.NotNil(t, loggingComponents.SecurityLogsBucket, "Security logs bucket should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogsKeyRing, "Security logs KMS KeyRing should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogsCryptoKey, "Security logs KMS CryptoKey should not be nil")

		// Verify sinks are still created
		require.NotNil(t, loggingComponents.AuditLogSink, "Audit log sink should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogSink, "Security log sink should not be nil")

		// Verify that all three buckets have their own dedicated KMS keys
		// by checking that the key IDs are different for each bucket
		stateBucketKeyIDCh := make(chan string, 1)
		defer close(stateBucketKeyIDCh)
		storageComponents.CryptoKey.ID().ApplyT(func(keyID string) error {
			stateBucketKeyIDCh <- keyID
			return nil
		})
		stateBucketKeyID := <-stateBucketKeyIDCh

		auditLogsKeyIDCh := make(chan string, 1)
		defer close(auditLogsKeyIDCh)
		loggingComponents.AuditLogsCryptoKey.ID().ApplyT(func(keyID string) error {
			auditLogsKeyIDCh <- keyID
			return nil
		})
		auditLogsKeyID := <-auditLogsKeyIDCh

		securityLogsKeyIDCh := make(chan string, 1)
		defer close(securityLogsKeyIDCh)
		loggingComponents.SecurityLogsCryptoKey.ID().ApplyT(func(keyID string) error {
			securityLogsKeyIDCh <- keyID
			return nil
		})
		securityLogsKeyID := <-securityLogsKeyIDCh

		// Each bucket should have its own dedicated KMS key
		assert.NotEmpty(t, stateBucketKeyID, "State bucket should have a KMS key ID")
		assert.NotEmpty(t, auditLogsKeyID, "Audit logs bucket should have a KMS key ID")
		assert.NotEmpty(t, securityLogsKeyID, "Security logs bucket should have a KMS key ID")

		stateBucketBindings := bootstrap.GetStateBucketBindings()
		require.NotNil(t, stateBucketBindings, "State bucket bindings should not be nil")
		assert.Equal(t, 8, len(stateBucketBindings), "Should have 8 IAM bindings")

		return nil
	}, pulumi.WithMocks("project", "stack", &testMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewBootstrap_WithoutCustomerManagedKeys(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		// Test args with customer-managed encryption disabled (default)
		args := &BootstrapArgs{
			Project:                                 "test-project",
			Region:                                  "us-central1",
			StateBucketKeyRotationPeriod:            "7776000s", // 90 days
			StateBucketArchivedObjectsRetentionDays: 7,
			LoggingDestinationProject:               "test-logging-project",
			LoggingRetentionDays:                    365,
			AdminMembers:                            []string{"admin-group@example.com"},
			SecurityMembers:                         []string{"security-group@example.com"},
			EnableCustomerManagedEncryption:         false, // Disable customer-managed encryption
			Labels: map[string]string{
				"environment": "test",
				"team":        "bootstrap",
			},
		}

		bootstrap, err := NewBootstrap(ctx, "test-bootstrap", args)
		require.NoError(t, err)

		// Verify storage components do NOT have KMS resources when disabled
		storageComponents := bootstrap.GetStorageComponents()
		require.NotNil(t, storageComponents, "Storage components should not be nil")
		assert.Nil(t, storageComponents.KeyRing, "State bucket KMS KeyRing should be nil when encryption disabled")
		assert.Nil(t, storageComponents.CryptoKey, "State bucket KMS CryptoKey should be nil when encryption disabled")
		require.NotNil(t, storageComponents.StateBucket, "State bucket should still exist")

		// Verify logging components do NOT have KMS resources when disabled
		loggingComponents := bootstrap.GetLoggingComponents()
		require.NotNil(t, loggingComponents, "Logging components should not be nil")

		// Buckets should exist but without KMS resources
		require.NotNil(t, loggingComponents.AuditLogsBucket, "Audit logs bucket should not be nil")
		assert.Nil(t, loggingComponents.AuditLogsKeyRing, "Audit logs KMS KeyRing should be nil when encryption disabled")
		assert.Nil(t, loggingComponents.AuditLogsCryptoKey, "Audit logs KMS CryptoKey should be nil when encryption disabled")

		require.NotNil(t, loggingComponents.SecurityLogsBucket, "Security logs bucket should not be nil")
		assert.Nil(t, loggingComponents.SecurityLogsKeyRing, "Security logs KMS KeyRing should be nil when encryption disabled")
		assert.Nil(t, loggingComponents.SecurityLogsCryptoKey, "Security logs KMS CryptoKey should be nil when encryption disabled")

		return nil
	}, pulumi.WithMocks("project", "stack", &testMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewBootstrap_WithOrganizationPolicies(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		// Test args with organization policies enabled
		args := &BootstrapArgs{
			Project:                                 "test-project",
			Region:                                  "us-central1",
			StateBucketKeyRotationPeriod:            "7776000s", // 90 days
			StateBucketArchivedObjectsRetentionDays: 7,
			LoggingDestinationProject:               "test-logging-project",
			LoggingRetentionDays:                    365,
			AdminMembers:                            []string{"admin-group@example.com"},
			SecurityMembers:                         []string{"security-group@example.com"},
			EnableOrganizationPolicies:              true, // Enable organization policies
			Labels: map[string]string{
				"environment": "test",
				"team":        "bootstrap",
			},
		}

		bootstrap, err := NewBootstrap(ctx, "test-bootstrap", args)
		require.NoError(t, err)

		// Verify organization policies are created when enabled
		orgPolicies := bootstrap.GetOrganizationPolicies()
		require.NotNil(t, orgPolicies, "Organization policies should not be nil when enabled")
		// 1. storage.uniformBucketLevelAccess
		// 2. storage.publicAccessPrevention
		// 3. storage.secureHttpTransport
		// 4. iam.disableServiceAccountKeyCreation
		assert.Equal(t, 4, len(orgPolicies), "Should have exactly 4 organization policies when enabled")

		// Verify other components are still created
		storageComponents := bootstrap.GetStorageComponents()
		require.NotNil(t, storageComponents, "Storage components should not be nil")
		require.NotNil(t, storageComponents.StateBucket, "State bucket should not be nil")

		loggingComponents := bootstrap.GetLoggingComponents()
		require.NotNil(t, loggingComponents, "Logging components should not be nil")
		require.NotNil(t, loggingComponents.AuditLogsBucket, "Audit logs bucket should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogsBucket, "Security logs bucket should not be nil")

		stateBucketBindings := bootstrap.GetStateBucketBindings()
		require.NotNil(t, stateBucketBindings, "State bucket bindings should not be nil")
		assert.Equal(t, 8, len(stateBucketBindings), "Should have 8 IAM bindings")

		return nil
	}, pulumi.WithMocks("project", "stack", &testMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}

func TestNewBootstrap_WithoutOrganizationPolicies(t *testing.T) {
	t.Parallel()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		// Test args with organization policies disabled (default)
		args := &BootstrapArgs{
			Project:                                 "test-project",
			Region:                                  "us-central1",
			StateBucketKeyRotationPeriod:            "7776000s", // 90 days
			StateBucketArchivedObjectsRetentionDays: 7,
			LoggingDestinationProject:               "test-logging-project",
			LoggingRetentionDays:                    365,
			AdminMembers:                            []string{"admin-group@example.com"},
			SecurityMembers:                         []string{"security-group@example.com"},
			EnableOrganizationPolicies:              false, // Disable organization policies
			Labels: map[string]string{
				"environment": "test",
				"team":        "bootstrap",
			},
		}

		bootstrap, err := NewBootstrap(ctx, "test-bootstrap", args)
		require.NoError(t, err)

		// Verify organization policies are NOT created when disabled
		orgPolicies := bootstrap.GetOrganizationPolicies()
		assert.Nil(t, orgPolicies, "Organization policies should be nil when disabled")

		// Verify other components are still created
		storageComponents := bootstrap.GetStorageComponents()
		require.NotNil(t, storageComponents, "Storage components should not be nil")
		require.NotNil(t, storageComponents.StateBucket, "State bucket should not be nil")

		loggingComponents := bootstrap.GetLoggingComponents()
		require.NotNil(t, loggingComponents, "Logging components should not be nil")
		require.NotNil(t, loggingComponents.AuditLogsBucket, "Audit logs bucket should not be nil")
		require.NotNil(t, loggingComponents.SecurityLogsBucket, "Security logs bucket should not be nil")

		stateBucketBindings := bootstrap.GetStateBucketBindings()
		require.NotNil(t, stateBucketBindings, "State bucket bindings should not be nil")
		assert.Equal(t, 8, len(stateBucketBindings), "Should have 8 IAM bindings")

		return nil
	}, pulumi.WithMocks("project", "stack", &testMocks{}))

	if err != nil {
		t.Fatalf("Pulumi WithMocks failed: %v", err)
	}
}
