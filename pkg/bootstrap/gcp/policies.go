package gcp

import (
	"fmt"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/projects"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// setupSecurityPolicies creates project-level organization policy constraints for security
func (b *Bootstrap) setupSecurityPolicies(ctx *pulumi.Context, config *BootstrapArgs) ([]*projects.OrganizationPolicy, error) {
	var orgPolicies []*projects.OrganizationPolicy

	// Require uniform bucket-level access
	policyName := b.NewResourceName("require-uniform-bucket-access", "org-constraint", 63)
	requireUniformBucketAccess, err := projects.NewOrganizationPolicy(ctx, policyName, &projects.OrganizationPolicyArgs{
		Project:    pulumi.String(config.Project),
		Constraint: pulumi.String("storage.uniformBucketLevelAccess"),
		BooleanPolicy: &projects.OrganizationPolicyBooleanPolicyArgs{
			Enforced: pulumi.Bool(true),
		},
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create uniform bucket access policy: %w", err)
	}
	orgPolicies = append(orgPolicies, requireUniformBucketAccess)

	// Restrict public bucket access
	policyName = b.NewResourceName("restrict-public-bucket-access", "org-constraint", 63)
	restrictPublicBucketAccess, err := projects.NewOrganizationPolicy(ctx, policyName, &projects.OrganizationPolicyArgs{
		Project:    pulumi.String(config.Project),
		Constraint: pulumi.String("storage.publicAccessPrevention"),
		BooleanPolicy: &projects.OrganizationPolicyBooleanPolicyArgs{
			Enforced: pulumi.Bool(true),
		},
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create public bucket access policy: %w", err)
	}
	orgPolicies = append(orgPolicies, restrictPublicBucketAccess)

	// Require HTTPS for buckets
	policyName = b.NewResourceName("require-bucket-https", "org-constraint", 63)
	requireHTTPS, err := projects.NewOrganizationPolicy(ctx, policyName, &projects.OrganizationPolicyArgs{
		Project:    pulumi.String(config.Project),
		Constraint: pulumi.String("storage.secureHttpTransport"),
		BooleanPolicy: &projects.OrganizationPolicyBooleanPolicyArgs{
			Enforced: pulumi.Bool(true),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTPS requirement policy: %w", err)
	}
	orgPolicies = append(orgPolicies, requireHTTPS)

	policyName = b.NewResourceName("disable-service-account-key-creation", "org-constraint", 63)
	disableAccountKeyCreation, err := projects.NewOrganizationPolicy(ctx, policyName, &projects.OrganizationPolicyArgs{
		Project:    pulumi.String(config.Project),
		Constraint: pulumi.String("iam.disableServiceAccountKeyCreation"),
		BooleanPolicy: &projects.OrganizationPolicyBooleanPolicyArgs{
			// TODO make me configurable
			Enforced: pulumi.Bool(true),
		},
	}, pulumi.Parent(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create service account key creation policy: %w", err)
	}
	orgPolicies = append(orgPolicies, disableAccountKeyCreation)

	return orgPolicies, nil
}
