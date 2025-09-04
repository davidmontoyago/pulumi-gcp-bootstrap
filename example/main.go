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
		log.Printf("GCP Project: %s", cfg.Project)
		log.Printf("GCP Region: %s", cfg.Region)

		// Convert config to bootstrap args using helper method
		args := cfg.ToBootstrapArgs()

		// Add default labels if none specified
		if args.Labels == nil {
			args.Labels = make(map[string]string)
		}
		args.Labels["project"] = cfg.Project
		args.Labels["purpose"] = "day-1-infrastructure"

		// Deploy bootstrap infrastructure
		bootstrap, err := gcp.NewBootstrap(ctx, "bootstrap", args)
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
		ctx.Export("keyRingLocation", pulumi.String(cfg.Region))
		ctx.Export("project", pulumi.String(cfg.Project))

		log.Println("Bootstrap infrastructure deployment completed successfully!")

		return nil
	})
}
