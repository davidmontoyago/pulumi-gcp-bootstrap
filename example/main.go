// Package main provides the entry point for the Pulumi GCP Bootstrap application.
package main

import (
	"log"

	"github.com/davidmontoyago/pulumi-gcp-bootstrap/pkg/bootstrap/config"
	"github.com/davidmontoyago/pulumi-gcp-bootstrap/pkg/bootstrap/gcp"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Load configuration from environment variables
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		// Log the stack and project for verification
		log.Printf("Deploying bootstrap infrastructure to stack: %s", ctx.Stack())
		log.Printf("GCP Project: %s", cfg.GCPProject)
		log.Printf("GCP Region: %s", cfg.GCPRegion)

		// Create bootstrap infrastructure with comprehensive security
		bootstrap, err := gcp.NewBootstrap(ctx, "bootstrap", &gcp.BootstrapArgs{
			Project:                      cfg.GCPProject,
			Region:                       cfg.GCPRegion,
			StateBucketKeyRotationPeriod: cfg.KMSKeyRotationPeriod,
			LoggingDestinationProject:    cfg.LoggingDestinationProject,
			LoggingRetentionDays:         cfg.LoggingRetentionDays,
			Labels: map[string]string{
				"project": cfg.GCPProject,
				"purpose": "day-1-infrastructure",
			},
		})
		if err != nil {
			return err
		}

		// Export important outputs for other stacks and tooling
		ctx.Export("stateBucketName", bootstrap.GetStateBucketName())
		ctx.Export("stateBucketURL", bootstrap.GetStateBucketURL())
		ctx.Export("kmsKeyID", pulumi.ToSecret(bootstrap.GetKMSKeyID()))
		ctx.Export("auditLogsBucketName", bootstrap.GetAuditLogsBucketName())
		ctx.Export("securityLogsBucketName", bootstrap.GetSecurityLogsBucketName())

		// Additional outputs for state management
		ctx.Export("keyRingLocation", pulumi.String(cfg.GCPRegion))
		ctx.Export("project", pulumi.String(cfg.GCPProject))
		ctx.Export("environment", pulumi.String(cfg.Environment))

		log.Println("Bootstrap infrastructure deployment completed successfully!")

		return nil
	})
}
