// Package gcp provides comprehensive GCP bootstrap infrastructure with security best practices
package gcp

import (
	"fmt"
	"maps"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// BootstrapComponents holds all the bootstrap infrastructure components
type BootstrapComponents struct {
	pulumi.ResourceState
	Namer

	labels map[string]string

	storage             *StorageComponents
	logging             *LoggingComponents
	policies            []*projects.OrganizationPolicy
	stateBucketBindings []*storage.BucketIAMMember
}

// NewBootstrap creates a new bootstrap infrastructure stack with all components
func NewBootstrap(ctx *pulumi.Context, name string, args *BootstrapArgs) (*BootstrapComponents, error) {
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

	bootstrapComponents := &BootstrapComponents{
		Namer: *NewNamer(name),

		labels: defaultLabels,
	}

	err := bootstrapComponents.deploy(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy bootstrap components: %w", err)
	}

	err = ctx.RegisterResourceOutputs(bootstrapComponents, pulumi.Map{
		"stateBucketName":        bootstrapComponents.GetStateBucketName(),
		"stateBucketURL":         bootstrapComponents.GetStateBucketURL(),
		"stateBucketKMSKeyID":    bootstrapComponents.GetKMSKeyID(),
		"auditLogsBucketName":    bootstrapComponents.GetAuditLogsBucketName(),
		"securityLogsBucketName": bootstrapComponents.GetSecurityLogsBucketName(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register resource outputs: %w", err)
	}

	return bootstrapComponents, nil
}

func (b *BootstrapComponents) deploy(ctx *pulumi.Context, args *BootstrapArgs) error {
	stateBucketComponents, err := b.createSecureStateBucket(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create storage components: %w", err)
	}
	b.storage = stateBucketComponents

	bucketBindings, err := b.setupIAMBindingsForStateBucket(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create bucket bindings: %w", err)
	}
	b.stateBucketBindings = bucketBindings

	loggingComponents, err := b.createSecureLoggingSinks(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create logging components: %w", err)
	}
	b.logging = loggingComponents

	policies, err := b.setupSecurityPolicies(ctx, args)
	if err != nil {
		return fmt.Errorf("failed to create org security policies: %w", err)
	}
	b.policies = policies

	return nil
}

// GetStateBucketName returns the state bucket name
func (b *BootstrapComponents) GetStateBucketName() pulumi.StringOutput {
	return b.storage.StateBucket.Name
}

// GetStateBucketURL returns the state bucket URL
func (b *BootstrapComponents) GetStateBucketURL() pulumi.StringOutput {
	return b.storage.StateBucket.Url
}

// GetKMSKeyID returns the KMS crypto key ID
func (b *BootstrapComponents) GetKMSKeyID() pulumi.IDOutput {
	return b.storage.CryptoKey.ID()
}

// GetAuditLogsBucketName returns the audit logs bucket name
func (b *BootstrapComponents) GetAuditLogsBucketName() pulumi.StringOutput {
	return b.logging.AuditLogsBucket.Name
}

// GetSecurityLogsBucketName returns the security logs bucket name
func (b *BootstrapComponents) GetSecurityLogsBucketName() pulumi.StringOutput {
	return b.logging.SecurityLogsBucket.Name
}

// TODO add missing getters
