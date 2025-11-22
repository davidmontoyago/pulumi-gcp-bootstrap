// Package gcp provides GCP bootstrap infrastructure components
package gcp

import (
	"fmt"
	"maps"
	"strings"

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
	KeyRing             *kms.KeyRing
	CryptoKey           *kms.CryptoKey
	StateBucket         *storage.Bucket
	stateBucketBindings []*storage.BucketIAMMember
}

// createSecureStateBucket creates a secure GCS bucket for infrastructure state with best practices
func (b *Bootstrap) createSecureStateBucket(ctx *pulumi.Context, config *BootstrapArgs) (*StorageComponents, error) {
	bucketDeps := []pulumi.Resource{}

	stateBucketLabels := maps.Clone(b.labels)
	stateBucketLabels["purpose"] = "infrastructure-state"

	// Create secure storage bucket with comprehensive security settings
	stateBucketName := b.NewResourceName("state", "bucket", 63)
	stateBucketArgs := &storage.BucketArgs{
		Name:     pulumi.Sprintf(stateBucketName),
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.Project),

		UniformBucketLevelAccess: pulumi.Bool(true),
		PublicAccessPrevention:   pulumi.String("enforced"),

		Versioning: &storage.BucketVersioningArgs{
			Enabled: pulumi.Bool(true),
		},

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

		Labels: mapToStringMapInput(stateBucketLabels),

		ForceDestroy: pulumi.Bool(config.ForceDestroy),
	}

	// Prepare response
	storageComponents := &StorageComponents{}

	if config.EnableCustomerManagedEncryption {
		// Create customer-managed key ring and key for encryption
		keyRing, cryptoKey, err := b.createEncryptionKey(ctx, config)
		if err != nil {
			return nil, err
		}

		// Add encryption key to state bucket
		stateBucketArgs.Encryption = &storage.BucketEncryptionArgs{
			DefaultKmsKeyName: cryptoKey.ID(),
		}

		storageComponents.KeyRing = keyRing
		storageComponents.CryptoKey = cryptoKey

		bucketDeps = append(bucketDeps, cryptoKey)
	}

	bucket, err := storage.NewBucket(ctx, stateBucketName, stateBucketArgs,
		pulumi.Parent(b), pulumi.DependsOn(bucketDeps))
	if err != nil {
		return nil, fmt.Errorf("failed to create state bucket: %w", err)
	}
	storageComponents.StateBucket = bucket

	return storageComponents, nil
}

func (b *Bootstrap) setupIAMBindingsForStateBucket(ctx *pulumi.Context, config *BootstrapArgs) ([]*storage.BucketIAMMember, error) {
	var bucketBindings []*storage.BucketIAMMember

	// Create bucket IAM member bindings for admin groups on audit logs bucket
	for _, adminGroup := range config.AdminMembers {

		adminGroupMember := adminGroup
		if !strings.Contains(adminGroup, ":") {
			// Default to group if not prefixed
			adminGroupMember = fmt.Sprintf("group:%s", adminGroup)
		}

		for _, role := range loggingAdminRoles {
			memberName := b.NewResourceName(fmt.Sprintf("audit-logs-admin-%s-%s", adminGroup, role), "iam-member", 63)
			auditLogAdminMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Audit logs bucket
				Bucket: b.auditLogs.LogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(adminGroupMember),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.auditLogs.LogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create audit logs admin IAM member for group %s: %w", adminGroup, err)
			}
			bucketBindings = append(bucketBindings, auditLogAdminMember)

			memberName = b.NewResourceName(fmt.Sprintf("security-logs-admin-%s-%s", adminGroup, role), "iam-member", 63)
			securityLogAdminMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Security logs bucket
				Bucket: b.securityLogs.LogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(adminGroupMember),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.securityLogs.LogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create security logs admin IAM member for group %s: %w", adminGroup, err)
			}
			bucketBindings = append(bucketBindings, securityLogAdminMember)
		}
	}

	// Create bucket IAM member bindings for security groups on audit logs bucket
	for _, securityGroup := range config.SecurityMembers {

		securityGroupMember := securityGroup
		if !strings.Contains(securityGroup, ":") {
			// Default to group if not prexixed
			securityGroupMember = fmt.Sprintf("group:%s", securityGroup)
		}

		for _, role := range loggingSecurityRoles {
			memberName := b.NewResourceName(fmt.Sprintf("audit-logs-security-%s-%s", securityGroup, role), "iam-member", 63)
			auditLogSecurityMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Audit logs bucket
				Bucket: b.auditLogs.LogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(securityGroupMember),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.auditLogs.LogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create audit logs security IAM member for group %s: %w", securityGroup, err)
			}
			bucketBindings = append(bucketBindings, auditLogSecurityMember)

			memberName = b.NewResourceName(fmt.Sprintf("security-logs-security-%s-%s", securityGroup, role), "iam-member", 63)
			securityLogSecurityMember, err := storage.NewBucketIAMMember(ctx, memberName, &storage.BucketIAMMemberArgs{
				// Security logs bucket
				Bucket: b.securityLogs.LogsBucket.Name,
				Role:   pulumi.String(role),
				Member: pulumi.String(securityGroupMember),
			}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{b.securityLogs.LogsBucket}))
			if err != nil {
				return nil, fmt.Errorf("failed to create security logs security IAM member for group %s: %w", securityGroup, err)
			}
			bucketBindings = append(bucketBindings, securityLogSecurityMember)
		}
	}

	return bucketBindings, nil
}
