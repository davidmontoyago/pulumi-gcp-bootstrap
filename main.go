package main

import (
	"log"

	"github.com/pulumi/pulumi-gcp/sdk/go/gcp/kms"
	"github.com/pulumi/pulumi-gcp/sdk/go/gcp/storage"
	"github.com/pulumi/pulumi/sdk/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		err := provisionInfraStateBucket(ctx)
		if err != nil {
			return err
		}

		// all other bootstrapped (day 1) infra here...

		return nil
	})
}

// Create an encrypted GCP storage bucket for Infrastructure State
func provisionInfraStateBucket(ctx *pulumi.Context) error {
	keyRing, err := kms.NewKeyRing(ctx, "bootstrap-key-ring", &kms.KeyRingArgs{
		Location: pulumi.String("us-central1"),
	})
	if err != nil {
		log.Println("failed to create KeyRing", err)
		return err
	}

	cryptoKey, err := kms.NewCryptoKey(ctx, "infra-state-store-key", &kms.CryptoKeyArgs{
		KeyRing:        keyRing.SelfLink,
		RotationPeriod: pulumi.String("100000s"),
	})
	if err != nil {
		log.Println("failed to create Key", err)
		return err
	}

	bucket, err := storage.NewBucket(ctx, "infra-state-store", &storage.BucketArgs{
		BucketPolicyOnly: pulumi.Bool(true),
		Encryption: storage.BucketEncryptionArgs{
			DefaultKmsKeyName: cryptoKey.SelfLink,
		},
		Location: pulumi.String("us-central1"),
	})
	if err != nil {
		log.Println("failed to provision Bucket", err)
		return err
	}

	ctx.Export("bucketName", bucket.Url)
	return nil
}
