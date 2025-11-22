// Package gcp provides comprehensive GCP bootstrap infrastructure with security best practices
package gcp

import (
	"fmt"
	"maps"

	namer "github.com/davidmontoyago/commodity-namer"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Bootstrap holds all the bootstrap infrastructure components
type Bootstrap struct {
	pulumi.ResourceState
	namer.Namer

	labels map[string]string

	storage      *StorageComponents
	auditLogs    *LoggingSinkBucket
	securityLogs *LoggingSinkBucket
	orgPolicies  []*projects.OrganizationPolicy
}

// NewBootstrap creates a new bootstrap infrastructure stack with all components
func NewBootstrap(ctx *pulumi.Context, name string, args *BootstrapArgs, opts ...pulumi.ResourceOption) (*Bootstrap, error) {
	if args == nil {
		return nil, fmt.Errorf("args are required")
	}

	// Default labels
	defaultLabels := map[string]string{
		"environment": name,
		"managed-by":  "pulumi-gcp-bootstrap",
	}

	// Merge with provided labels
	if args.Labels != nil {
		maps.Copy(defaultLabels, args.Labels)
	}

	bootstrap := &Bootstrap{
		Namer: namer.New(name, namer.WithReplace()),

		labels: defaultLabels,
	}

	err := ctx.RegisterComponentResource("pulumi-gcp-bootstrap:gcp:Bootstrap", name, bootstrap, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to register component resource: %w", err)
	}

	// Deploy the infrastructure
	err = bootstrap.deploy(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy bootstrap components: %w", err)
	}

	err = ctx.RegisterResourceOutputs(bootstrap, pulumi.Map{
		"stateBucketName":        bootstrap.GetStateBucketName(),
		"stateBucketURL":         bootstrap.GetStateBucketURL(),
		"auditLogsBucketName":    bootstrap.GetAuditLogsBucketName(),
		"auditLogsBucketURL":     bootstrap.GetAuditLogsBucketURL(),
		"securityLogsBucketName": bootstrap.GetSecurityLogsBucketName(),
		"securityLogsBucketURL":  bootstrap.GetSecurityLogsBucketURL(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register resource outputs: %w", err)
	}

	return bootstrap, nil
}

func (b *Bootstrap) deploy(ctx *pulumi.Context, args *BootstrapArgs) error {
	stateBucketComponents, err := b.createSecureStateBucket(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create storage components: %w", err)
	}
	b.storage = stateBucketComponents

	auditLogsStorage, securityLogsStorage, err := b.createSecureLoggingSinks(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create logging components: %w", err)
	}
	b.auditLogs = auditLogsStorage
	b.securityLogs = securityLogsStorage

	bucketBindings, err := b.setupIAMBindingsForStateBucket(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create bucket bindings: %w", err)
	}
	b.storage.stateBucketBindings = bucketBindings

	policies, err := b.setupOrgSecurityPolicies(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create org security policies: %w", err)
	}
	b.orgPolicies = policies

	return nil
}

// GetStateBucketName returns the state bucket name
func (b *Bootstrap) GetStateBucketName() pulumi.StringOutput {
	return b.storage.StateBucket.Name
}

// GetStateBucketURL returns the state bucket URL
func (b *Bootstrap) GetStateBucketURL() pulumi.StringOutput {
	return b.storage.StateBucket.Url
}

// GetKMSKeyID returns the KMS crypto key ID
func (b *Bootstrap) GetKMSKeyID() pulumi.IDOutput {
	return b.storage.CryptoKey.ID()
}

// GetAuditLogsBucketName returns the audit logs bucket name
func (b *Bootstrap) GetAuditLogsBucketName() pulumi.StringOutput {
	return b.auditLogs.LogsBucket.Name
}

// GetSecurityLogsBucketName returns the security logs bucket name
func (b *Bootstrap) GetSecurityLogsBucketName() pulumi.StringOutput {
	return b.securityLogs.LogsBucket.Name
}

// GetStorageComponents returns the storage components
func (b *Bootstrap) GetStorageComponents() *StorageComponents {
	return b.storage
}

// GetOrganizationPolicies returns the organization policies
func (b *Bootstrap) GetOrganizationPolicies() []*projects.OrganizationPolicy {
	return b.orgPolicies
}

// GetStateBucketBindings returns the state bucket IAM bindings
func (b *Bootstrap) GetStateBucketBindings() []*storage.BucketIAMMember {
	if b.storage == nil {
		return nil
	}

	return b.storage.stateBucketBindings
}

// GetAuditLogsBucketURL returns the audit logs bucket URL
func (b *Bootstrap) GetAuditLogsBucketURL() pulumi.StringOutput {
	return b.auditLogs.LogsBucket.Url
}

// GetSecurityLogsBucketURL returns the security logs bucket URL
func (b *Bootstrap) GetSecurityLogsBucketURL() pulumi.StringOutput {
	return b.securityLogs.LogsBucket.Url
}

// GetAuditLogsSinkBucket returns the audit logs sink bucket components
func (b *Bootstrap) GetAuditLogsSinkBucket() *LoggingSinkBucket {
	return b.auditLogs
}

// GetSecurityLogsSinkBucket returns the security logs sink bucket components
func (b *Bootstrap) GetSecurityLogsSinkBucket() *LoggingSinkBucket {
	return b.securityLogs
}
