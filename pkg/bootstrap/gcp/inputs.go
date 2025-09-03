package gcp

// BootstrapArgs contains the arguments for creating bootstrap infrastructure
type BootstrapArgs struct {
	// GCP project to bootstrap. Required.
	Project string
	// GCP region to bootstrap. Required.
	Region string

	// Period of time to rotate the KMS key for the state bucket
	StateBucketKeyRotationPeriod string
	// Number of days to retain archived objects in the infra state bucket
	StateBucketArchivedObjectsRetentionDays int

	// Project to which audit and security logs will be exported
	LoggingDestinationProject string
	// Number of days to retain audit and security logs. Defaults to 365 days.
	LoggingRetentionDays int

	// List of member groups are allowed to administer the infrastructure
	AdminMembers []string
	// List of member groups are allowed to audit the infrastructure as security admins
	SecurityMembers []string

	// Labels to be applied to the resources
	Labels map[string]string
}
