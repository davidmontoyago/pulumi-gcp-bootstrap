package main

import (
	"github.com/pulumi/pulumi-gcp/sdk/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Create a GCP storage bucket for Infrastructure State
		bucket, err := storage.NewBucket(ctx, "infra-state-store", nil)
		if err != nil {
			return err
		}

		// Export the DNS name of the bucket
		ctx.Export("bucketName", bucket.Url)
		return nil
	})
}
