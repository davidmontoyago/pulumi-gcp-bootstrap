package gcp

import (
	"fmt"
	"maps"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/logging"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// LoggingComponents holds the logging-related infrastructure components
type LoggingComponents struct {
	AuditLogsBucket    *storage.Bucket
	SecurityLogsBucket *storage.Bucket
	AuditLogSink       *logging.ProjectSink
	SecurityLogSink    *logging.ProjectSink
}

// createSecureLoggingSinks creates secure logging infrastructure with best practices
func (b *Bootstrap) createSecureLoggingSinks(ctx *pulumi.Context, config *BootstrapArgs) (*LoggingComponents, error) {

	// Create dedicated bucket for audit logs
	auditLogsBucketLabels := maps.Clone(b.labels)
	auditLogsBucketLabels["purpose"] = "audit-logs"
	auditLogsBucketName := b.NewResourceName("audit-logs", "bucket", 63)
	auditLogsBucket, err := storage.NewBucket(ctx, auditLogsBucketName, &storage.BucketArgs{
		Name:     pulumi.String(auditLogsBucketName),
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.LoggingDestinationProject),

		// Security settings
		UniformBucketLevelAccess: pulumi.Bool(true),
		PublicAccessPrevention:   pulumi.String("enforced"),

		// Versioning for log protection
		Versioning: &storage.BucketVersioningArgs{
			Enabled: pulumi.Bool(true),
		},

		// Similar lifecycle rules as audit logs
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
		Labels: mapToStringMapInput(auditLogsBucketLabels),
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logs bucket: %w", err)
	}

	// Create dedicated bucket for security logs
	securityLogsBucketLabels := maps.Clone(b.labels)
	securityLogsBucketLabels["purpose"] = "security-logs"
	securityLogsBucketName := b.NewResourceName("security-logs", "bucket", 63)
	securityLogsBucket, err := storage.NewBucket(ctx, securityLogsBucketName, &storage.BucketArgs{
		Name:     pulumi.String(securityLogsBucketName),
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.LoggingDestinationProject),

		// Security settings
		UniformBucketLevelAccess: pulumi.Bool(true),
		PublicAccessPrevention:   pulumi.String("enforced"),

		// Encryption with Google-managed keys (default encryption enabled)
		Encryption: &storage.BucketEncryptionArgs{},

		// Versioning for log protection
		Versioning: &storage.BucketVersioningArgs{
			Enabled: pulumi.Bool(true),
		},

		// Similar lifecycle rules as audit logs
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
		Labels: mapToStringMapInput(securityLogsBucketLabels),
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create security logs bucket: %w", err)
	}

	// Create audit log sink for comprehensive audit trail
	auditLogSinkName := b.NewResourceName("audit-sink", "sink", 63)
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

	// Create security log sink for security-related events
	securityLogSinkName := b.NewResourceName("security-sink", "sink", 63)
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

	return &LoggingComponents{
		AuditLogsBucket:    auditLogsBucket,
		SecurityLogsBucket: securityLogsBucket,
		AuditLogSink:       auditLogSink,
		SecurityLogSink:    securityLogSink,
	}, nil
}
