package gcp

import "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

func mapToStringMapInput(m map[string]string) pulumi.StringMap {
	result := pulumi.StringMap{}
	for k, v := range m {
		result[k] = pulumi.String(v)
	}

	return result
}
