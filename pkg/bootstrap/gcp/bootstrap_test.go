package gcp

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func TestNewBootstrap_HappyPath(t *testing.T) {
}

// testMocks implements pulumi.MockResourceMonitor for testing
type testMocks struct{}

func (m *testMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	outputs := resource.PropertyMap{}

	// Add common outputs based on resource type
	switch args.TypeToken {
	case "gcp:storage/bucket:Bucket":
		outputs["name"] = resource.NewStringProperty("test-bucket")
		outputs["url"] = resource.NewStringProperty("gs://test-bucket")
	case "gcp:kms/keyRing:KeyRing":
		outputs["id"] = resource.NewStringProperty("test-keyring")
		outputs["selfLink"] = resource.NewStringProperty("https://cloudkms.googleapis.com/v1/projects/test-project/locations/us-central1/keyRings/test-keyring")
	case "gcp:kms/cryptoKey:CryptoKey":
		outputs["id"] = resource.NewStringProperty("test-crypto-key")
		outputs["selfLink"] = resource.NewStringProperty("https://cloudkms.googleapis.com/v1/projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-crypto-key")
	case "gcp:logging/projectSink:ProjectSink":
		outputs["id"] = resource.NewStringProperty("test-sink")
		outputs["writerIdentity"] = resource.NewStringProperty("serviceAccount:test@test-project.iam.gserviceaccount.com")
	case "gcp:storage/bucketIAMPolicy:BucketIAMPolicy":
		outputs["etag"] = resource.NewStringProperty("test-etag")
	case "gcp:projects/organizationPolicy:OrganizationPolicy":
		outputs["etag"] = resource.NewStringProperty("test-policy-etag")
	}

	return args.Name + "-id", outputs, nil
}

func (m *testMocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}
