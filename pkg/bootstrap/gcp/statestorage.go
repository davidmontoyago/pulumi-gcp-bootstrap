// Package gcp provides GCP bootstrap infrastructure components
package gcp

import (
	"fmt"
	"maps"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/kms"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var (
	loggingAdminRoles = []string{
		"roles/storage.admin",
		"roles/storage.objectAdmin",
	}
	loggingSecurityRoles = []string{
		"roles/storage.objectViewer",
		"roles/storage.legacyBucketReader",
	}
)

// StorageComponents holds the storage-related infrastructure components
type StorageComponents struct {
	KeyRing     *kms.KeyRing
	CryptoKey   *kms.CryptoKey
	StateBucket *storage.Bucket
}

// createSecureStateBucket creates a secure GCS bucket for infrastructure state with best practices
func (b *BootstrapComponents) createSecureStateBucket(ctx *pulumi.Context, config *BootstrapArgs) (*StorageComponents, error) {

	// Create KMS key ring for encryption
	keyRingName := b.NewResourceName("state-bucket-key-ring", "kms", 63)
	keyRing, err := kms.NewKeyRing(ctx, keyRingName, &kms.KeyRingArgs{
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.Project),
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS key ring: %w", err)
	}

	// Create crypto key for bucket encryption with rotation
	cryptoKeyName := b.NewResourceName("state-bucket-crypto-key", "kms", 63)
	cryptoKey, err := kms.NewCryptoKey(ctx, cryptoKeyName, &kms.CryptoKeyArgs{
		KeyRing:        keyRing.ID(),
		RotationPeriod: pulumi.String(config.StateBucketKeyRotationPeriod),
		VersionTemplate: &kms.CryptoKeyVersionTemplateArgs{
			Algorithm:       pulumi.String("GOOGLE_SYMMETRIC_ENCRYPTION"),
			ProtectionLevel: pulumi.String("SOFTWARE"),
		},
		Purpose: pulumi.String("ENCRYPT_DECRYPT"),
	}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{keyRing}))
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto key: %w", err)
	}

	stateBucketLabels := maps.Clone(b.labels)
	stateBucketLabels["purpose"] = "infrastructure-state"

	// Create secure storage bucket with comprehensive security settings
	stateBucketName := b.NewResourceName("state", "bucket", 63)
	bucket, err := storage.NewBucket(ctx, stateBucketName, &storage.BucketArgs{
		Name:     pulumi.Sprintf(stateBucketName),
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.Project),

		// Security settings
		UniformBucketLevelAccess: pulumi.Bool(true),
		PublicAccessPrevention:   pulumi.String("enforced"),

		// Encryption with customer-managed key
		Encryption: &storage.BucketEncryptionArgs{
			DefaultKmsKeyName: cryptoKey.ID(),
		},

		// Versioning for state protection
		Versioning: &storage.BucketVersioningArgs{
			Enabled: pulumi.Bool(true),
		},

		// Delete archived older objects versions
		LifecycleRules: storage.BucketLifecycleRuleArray{
			&storage.BucketLifecycleRuleArgs{
				Action: &storage.BucketLifecycleRuleActionArgs{
					Type: pulumi.String("Delete"),
				},
				Condition: &storage.BucketLifecycleRuleConditionArgs{
					Age:              pulumi.Int(config.StateBucketArchivedObjectsRetentionDays),
					NumNewerVersions: pulumi.Int(3),
					WithState:        pulumi.String("ARCHIVED"),
				},
			},
		},

		// Retention policy
		RetentionPolicy: &storage.BucketRetentionPolicyArgs{
			IsLocked:        pulumi.Bool(false),                                                     // Can be enabled later for compliance
			RetentionPeriod: pulumi.Int(config.StateBucketArchivedObjectsRetentionDays * 24 * 3600), // Convert days to seconds
		},

		// Labels for resource management
		Labels: mapToStringMapInput(stateBucketLabels),
	}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{cryptoKey}))
	if err != nil {
		return nil, fmt.Errorf("failed to create state bucket: %w", err)
	}

	return &StorageComponents{
		KeyRing:     keyRing,
		CryptoKey:   cryptoKey,
		StateBucket: bucket,
	}, nil
}

func (b *BootstrapComponents) setupIAMBindingsForStateBucket(ctx *pulumi.Context, config *BootstrapArgs) ([]*storage.BucketIAMMember, error) {
	var bucketBindings []*storage.BucketIAMMember

	// Create bucket IAM member bindings for admin groups on audit logs bucket
	for _, adminGroup := range config.AdminGroups {
		for _, role := range loggingAdminRoles {
			memberName := b.NewResourceName(fmt.Sprintf("audit-logs-admin-%s", adminGroup), "iam-member", 63)
			auditLogAdminMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Audit logs bucket
				Bucket: b.logging.AuditLogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(fmt.Sprintf("group:%s", adminGroup)),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.logging.AuditLogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create audit logs admin IAM member for group %s: %w", adminGroup, err)
			}
			bucketBindings = append(bucketBindings, auditLogAdminMember)

			memberName = b.NewResourceName(fmt.Sprintf("security-logs-admin-%s", adminGroup), "iam-member", 63)
			securityLogAdminMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Security logs bucket
				Bucket: b.logging.SecurityLogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(fmt.Sprintf("group:%s", adminGroup)),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.logging.SecurityLogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create security logs admin IAM member for group %s: %w", adminGroup, err)
			}
			bucketBindings = append(bucketBindings, securityLogAdminMember)
		}
	}

	// Create bucket IAM member bindings for security groups on audit logs bucket
	for _, securityGroup := range config.SecurityGroups {
		for _, role := range loggingSecurityRoles {
			memberName := b.NewResourceName(fmt.Sprintf("audit-logs-security-%s", securityGroup), "iam-member", 63)
			auditLogSecurityMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Audit logs bucket
				Bucket: b.logging.AuditLogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(fmt.Sprintf("group:%s", securityGroup)),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.logging.AuditLogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create audit logs security IAM member for group %s: %w", securityGroup, err)
			}
			bucketBindings = append(bucketBindings, auditLogSecurityMember)

			memberName = b.NewResourceName(fmt.Sprintf("security-logs-security-%s", securityGroup), "iam-member", 63)
			securityLogSecurityMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Security logs bucket
				Bucket: b.logging.SecurityLogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(fmt.Sprintf("group:%s", securityGroup)),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.logging.SecurityLogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create security logs security IAM member for group %s: %w", securityGroup, err)
			}
			bucketBindings = append(bucketBindings, securityLogSecurityMember)
		}
	}

	return bucketBindings, nil
}
