package gcp

import (
	"fmt"
	"maps"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/kms"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/logging"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// LoggingSinkBucket is a bucket for a logging sink
type LoggingSinkBucket struct {
	LogsBucket            *storage.Bucket
	LogsKeyRing           *kms.KeyRing
	LogsCryptoKey         *kms.CryptoKey
	LogSink               *logging.ProjectSink
	LogsBucketIAMBindings []*storage.BucketIAMMember
}

// createSecureLoggingSinks creates secure logging infrastructure with best practices
func (b *Bootstrap) createSecureLoggingSinks(ctx *pulumi.Context, config *BootstrapArgs) (*LoggingSinkBucket, *LoggingSinkBucket, error) {

	auditLogsStorage, err := b.createAuditLogsBucket(config, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create audit logs bucket: %w", err)
	}

	securityLogsStorage, err := b.createSecurityLogsBucket(config, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create security logs bucket: %w", err)
	}

	// Create audit log sink for comprehensive audit trail
	auditLogSink, err := b.createAuditLogsSink(ctx, config, auditLogsStorage.LogsBucket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create audit log sink: %w", err)
	}
	auditLogsStorage.LogSink = auditLogSink

	// Create security log sink for security-related events
	securityLogSink, err := b.createSecurityLogsSink(ctx, config, securityLogsStorage.LogsBucket)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create security log sink: %w", err)
	}
	securityLogsStorage.LogSink = securityLogSink

	// Grant the sink permissions to use the bucket
	auditSinkIAMBindings, err := b.createSinkIAMBindings(ctx, "audit-logs", auditLogsStorage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to grant audit log sink bucket read permissions: %w", err)
	}
	auditLogsStorage.LogsBucketIAMBindings = auditSinkIAMBindings

	securitySinkIAMBindings, err := b.createSinkIAMBindings(ctx, "security-logs", securityLogsStorage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to grant security log sink bucket read permissions: %w", err)
	}
	securityLogsStorage.LogsBucketIAMBindings = securitySinkIAMBindings

	return auditLogsStorage, securityLogsStorage, nil
}

func (b *Bootstrap) createSinkIAMBindings(ctx *pulumi.Context, purpose string, loggingStorage *LoggingSinkBucket) ([]*storage.BucketIAMMember, error) {
	iamBindings := []*storage.BucketIAMMember{}

	objectWrite, err := storage.NewBucketIAMMember(ctx, b.NewResourceName(fmt.Sprintf("%s-sink-object-write", purpose), "iam-member", 63), &storage.BucketIAMMemberArgs{
		Bucket: loggingStorage.LogsBucket.Name,
		Role:   pulumi.String("roles/storage.objectCreator"),
		Member: loggingStorage.LogSink.WriterIdentity,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to grant audit log sink object write permissions: %w", err)
	}
	iamBindings = append(iamBindings, objectWrite)

	// Grant bucket metadata reading permissions (required for sinks)
	bucketRead, err := storage.NewBucketIAMMember(ctx, b.NewResourceName(fmt.Sprintf("%s-sink-bucket-read", purpose), "iam-member", 63), &storage.BucketIAMMemberArgs{
		Bucket: loggingStorage.LogsBucket.Name,
		Role:   pulumi.String("roles/storage.bucketViewer"),
		Member: loggingStorage.LogSink.WriterIdentity,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to grant audit log sink bucket read permissions: %w", err)
	}
	iamBindings = append(iamBindings, bucketRead)

	return iamBindings, nil
}

func (b *Bootstrap) createSecurityLogsSink(ctx *pulumi.Context, config *BootstrapArgs, securityLogsBucket *storage.Bucket) (*logging.ProjectSink, error) {
	securityLogSinkName := b.NewResourceName("security-logs", "sink", 63)
	securityLogSink, err := logging.NewProjectSink(ctx, securityLogSinkName, &logging.ProjectSinkArgs{
		Name:    pulumi.Sprintf(securityLogSinkName),
		Project: pulumi.String(config.Project),

		// Security-focused log filter
		Filter: pulumi.String(`(
			protoPayload.serviceName="iam.googleapis.com" OR
			protoPayload.serviceName="serviceusage.googleapis.com" OR
			protoPayload.serviceName="orgpolicy.googleapis.com" OR
			(protoPayload.serviceName="compute.googleapis.com" AND
				(protoPayload.methodName:"firewall" OR protoPayload.methodName:"route"))
		) OR
		severity="ERROR" OR severity="CRITICAL" OR
		jsonPayload.incident_id!="" OR
		jsonPayload.finding_id!="" OR
		resource.type="gce_firewall_rule" OR
		resource.type="vpc_flow_log"`),

		Destination: securityLogsBucket.Name.ApplyT(func(name string) string {
			return fmt.Sprintf("storage.googleapis.com/%s", name)
		}).(pulumi.StringOutput),

		// Enable unique writer identity for security
		UniqueWriterIdentity: pulumi.Bool(true),
	}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{securityLogsBucket}))
	if err != nil {
		return nil, fmt.Errorf("failed to create security log sink: %w", err)
	}
	return securityLogSink, nil
}

func (b *Bootstrap) createAuditLogsSink(ctx *pulumi.Context, config *BootstrapArgs, auditLogsBucket *storage.Bucket) (*logging.ProjectSink, error) {
	auditLogSinkName := b.NewResourceName("audit-logs", "sink", 63)
	auditLogSink, err := logging.NewProjectSink(ctx, auditLogSinkName, &logging.ProjectSinkArgs{
		Name:    pulumi.Sprintf(auditLogSinkName),
		Project: pulumi.String(config.Project),

		// Comprehensive audit log filter
		Filter: pulumi.String(`(
			protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR
			protoPayload.serviceName="iam.googleapis.com" OR
			protoPayload.serviceName="compute.googleapis.com" OR
			protoPayload.serviceName="storage.googleapis.com" OR
			protoPayload.serviceName="cloudsql.googleapis.com" OR
			protoPayload.serviceName="container.googleapis.com" OR
			logName:"cloudaudit.googleapis.com"
		) AND protoPayload.authenticationInfo.principalEmail!=""
		AND protoPayload.methodName!=""
		AND (
			protoPayload.methodName:"create" OR
			protoPayload.methodName:"delete" OR
			protoPayload.methodName:"update" OR
			protoPayload.methodName:"set" OR
			protoPayload.methodName:"add" OR
			protoPayload.methodName:"remove" OR
			protoPayload.methodName:"insert"
		)`),

		Destination: auditLogsBucket.Name.ApplyT(func(name string) string {
			return fmt.Sprintf("storage.googleapis.com/%s", name)
		}).(pulumi.StringOutput),

		// Enable unique writer identity for security
		UniqueWriterIdentity: pulumi.Bool(true),
	}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{auditLogsBucket}))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log sink: %w", err)
	}
	return auditLogSink, nil
}

func (b *Bootstrap) createSecurityLogsBucket(config *BootstrapArgs, ctx *pulumi.Context) (*LoggingSinkBucket, error) {
	logsSinkBucket := &LoggingSinkBucket{}

	securityBucketDeps := []pulumi.Resource{}

	// Create dedicated bucket for security logs
	securityLogsBucketLabels := maps.Clone(b.labels)
	securityLogsBucketLabels["purpose"] = "security-logs"
	securityLogsBucketName := b.NewResourceName("security-logs", "bucket", 63)
	securityLogsBucketArgs := newLoggingBucketDefaultArgs(securityLogsBucketName, config, securityLogsBucketLabels)

	if config.EnableCustomerManagedEncryption {
		// Create customer-managed key ring and key for encryption
		keyRing, cryptoKey, err := b.createEncryptionKey(ctx, config)
		if err != nil {
			return nil, err
		}

		// Add encryption key to security logs bucket
		securityLogsBucketArgs.Encryption = &storage.BucketEncryptionArgs{
			DefaultKmsKeyName: cryptoKey.ID(),
		}

		logsSinkBucket.LogsKeyRing = keyRing
		logsSinkBucket.LogsCryptoKey = cryptoKey

		securityBucketDeps = append(securityBucketDeps, cryptoKey)
	}

	securityLogsBucket, err := storage.NewBucket(ctx, securityLogsBucketName, securityLogsBucketArgs,
		pulumi.Parent(b), pulumi.DependsOn(securityBucketDeps))
	if err != nil {
		return nil, fmt.Errorf("failed to create security logs bucket: %w", err)
	}

	logsSinkBucket.LogsBucket = securityLogsBucket

	return logsSinkBucket, nil
}

func (b *Bootstrap) createAuditLogsBucket(config *BootstrapArgs, ctx *pulumi.Context) (*LoggingSinkBucket, error) {
	auditBucketDeps := []pulumi.Resource{}

	logsSinkBucket := &LoggingSinkBucket{}

	// Create dedicated bucket for audit logs
	auditLogsBucketLabels := maps.Clone(b.labels)
	auditLogsBucketLabels["purpose"] = "audit-logs"
	auditLogsBucketName := b.NewResourceName("audit-logs", "bucket", 63)
	auditLogsBucketArgs := newLoggingBucketDefaultArgs(auditLogsBucketName, config, auditLogsBucketLabels)

	if config.EnableCustomerManagedEncryption {
		// Create customer-managed key ring and key for encryption
		keyRing, cryptoKey, err := b.createEncryptionKey(ctx, config)
		if err != nil {
			return nil, err
		}

		// Add encryption key to audit logs bucket
		auditLogsBucketArgs.Encryption = &storage.BucketEncryptionArgs{
			DefaultKmsKeyName: cryptoKey.ID(),
		}

		logsSinkBucket.LogsKeyRing = keyRing
		logsSinkBucket.LogsCryptoKey = cryptoKey

		auditBucketDeps = append(auditBucketDeps, cryptoKey)
	}

	auditLogsBucket, err := storage.NewBucket(ctx, auditLogsBucketName, auditLogsBucketArgs,
		pulumi.Parent(b), pulumi.DependsOn(auditBucketDeps))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logs bucket: %w", err)
	}

	logsSinkBucket.LogsBucket = auditLogsBucket

	return logsSinkBucket, nil
}

func newLoggingBucketDefaultArgs(bucketName string, config *BootstrapArgs, bucketLabels map[string]string) *storage.BucketArgs {
	auditLogsBucketArgs := &storage.BucketArgs{
		Name:     pulumi.String(bucketName),
		Location: pulumi.String(config.Region),
		// TODO this may require a custom identity
		Project: pulumi.String(config.LoggingDestinationProject),

		UniformBucketLevelAccess: pulumi.Bool(true),
		PublicAccessPrevention:   pulumi.String("enforced"),

		Versioning: &storage.BucketVersioningArgs{
			Enabled: pulumi.Bool(true),
		},

		LifecycleRules: storage.BucketLifecycleRuleArray{
			&storage.BucketLifecycleRuleArgs{
				Action: &storage.BucketLifecycleRuleActionArgs{
					Type:         pulumi.String("SetStorageClass"),
					StorageClass: pulumi.String("NEARLINE"),
				},
				Condition: &storage.BucketLifecycleRuleConditionArgs{
					Age: pulumi.Int(30),
				},
			},
			&storage.BucketLifecycleRuleArgs{
				Action: &storage.BucketLifecycleRuleActionArgs{
					Type:         pulumi.String("SetStorageClass"),
					StorageClass: pulumi.String("COLDLINE"),
				},
				Condition: &storage.BucketLifecycleRuleConditionArgs{
					Age: pulumi.Int(90),
				},
			},
			&storage.BucketLifecycleRuleArgs{
				Action: &storage.BucketLifecycleRuleActionArgs{
					Type:         pulumi.String("SetStorageClass"),
					StorageClass: pulumi.String("ARCHIVE"),
				},
				Condition: &storage.BucketLifecycleRuleConditionArgs{
					Age: pulumi.Int(365),
				},
			},
			&storage.BucketLifecycleRuleArgs{
				Action: &storage.BucketLifecycleRuleActionArgs{
					Type: pulumi.String("Delete"),
				},
				Condition: &storage.BucketLifecycleRuleConditionArgs{
					Age: pulumi.Int(config.LoggingRetentionDays),
				},
			},
		},
		Labels: mapToStringMapInput(bucketLabels),
	}
	return auditLogsBucketArgs
}
