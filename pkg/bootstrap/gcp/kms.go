package gcp

import (
	"fmt"

	"github.com/pulumi/pulumi-gcp/sdk/v8/go/gcp/kms"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func (b *Bootstrap) createEncryptionKey(ctx *pulumi.Context, config *BootstrapArgs) (*kms.KeyRing, *kms.CryptoKey, error) {
	keyRingName := b.NewResourceName("state-bucket-key-ring", "kms", 63)
	keyRing, err := kms.NewKeyRing(ctx, keyRingName, &kms.KeyRingArgs{
		Location: pulumi.String(config.Region),
		Project:  pulumi.String(config.Project),
	}, pulumi.Parent(b))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create KMS key ring: %w", err)
	}

	// Create crypto key for bucket encryption with rotation
	cryptoKeyName := b.NewResourceName("state-bucket-crypto-key", "kms", 63)
	cryptoKey, err := kms.NewCryptoKey(ctx, cryptoKeyName, &kms.CryptoKeyArgs{
		KeyRing:        keyRing.ID(),
		RotationPeriod: pulumi.String(config.StateBucketKeyRotationPeriod),
		VersionTemplate: &kms.CryptoKeyVersionTemplateArgs{
			Algorithm:       pulumi.String("GOOGLE_SYMMETRIC_ENCRYPTION"),
			ProtectionLevel: pulumi.String("SOFTWARE"),
		},
		Purpose: pulumi.String("ENCRYPT_DECRYPT"),
	}, pulumi.Parent(b), pulumi.DependsOn([]pulumi.Resource{keyRing}))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create crypto key: %w", err)
	}
	return keyRing, cryptoKey, nil
}
