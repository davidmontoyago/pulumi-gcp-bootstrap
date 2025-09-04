// Package gcp provides comprehensive GCP bootstrap infrastructure with security best practices
package gcp

import (
	"fmt"
	"maps"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Bootstrap holds all the bootstrap infrastructure components
type Bootstrap struct {
	pulumi.ResourceState
	Namer

	labels map[string]string

	storage     *StorageComponents
	logging     *LoggingComponents
	orgPolicies []*projects.OrganizationPolicy
}

// NewBootstrap creates a new bootstrap infrastructure stack with all components
func NewBootstrap(ctx *pulumi.Context, name string, args *BootstrapArgs, opts ...pulumi.ResourceOption) (*Bootstrap, error) {
	if args == nil {
		return nil, fmt.Errorf("args are required")
	}

	// Default labels
	defaultLabels := map[string]string{
		"environment": "bootstrap",
		"managed-by":  "pulumi",
		"component":   "bootstrap",
	}

	// Merge with provided labels
	if args.Labels != nil {
		maps.Copy(defaultLabels, args.Labels)
	}

	bootstrap := &Bootstrap{
		Namer: *NewNamer(name),

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
		"stateBucketKMSKeyID":    bootstrap.GetKMSKeyID(),
		"auditLogsBucketName":    bootstrap.GetAuditLogsBucketName(),
		"securityLogsBucketName": bootstrap.GetSecurityLogsBucketName(),
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

	loggingComponents, err := b.createSecureLoggingSinks(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create logging components: %w", err)
	}
	b.logging = loggingComponents

	bucketBindings, err := b.setupIAMBindingsForStateBucket(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create bucket bindings: %w", err)
	}
	b.storage.stateBucketBindings = bucketBindings

	policies, err := b.setupSecurityPolicies(ctx, args)
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
	return b.logging.AuditLogsBucket.Name
}

// GetSecurityLogsBucketName returns the security logs bucket name
func (b *Bootstrap) GetSecurityLogsBucketName() pulumi.StringOutput {
	return b.logging.SecurityLogsBucket.Name
}

// GetStorageComponents returns the storage components
func (b *Bootstrap) GetStorageComponents() *StorageComponents {
	return b.storage
}

// GetLoggingComponents returns the logging components
func (b *Bootstrap) GetLoggingComponents() *LoggingComponents {
	return b.logging
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
