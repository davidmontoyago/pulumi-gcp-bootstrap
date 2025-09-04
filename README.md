# Pulumi GCP Bootstrap

[![Develop](https://github.com/davidmontoyago/pulumi-gcp-bootstrap/actions/workflows/develop.yaml/badge.svg)](https://github.com/davidmontoyago/pulumi-gcp-bootstrap/actions/workflows/develop.yaml) [![Go Coverage](https://raw.githubusercontent.com/wiki/davidmontoyago/pulumi-gcp-bootstrap/coverage.svg)](https://raw.githack.com/wiki/davidmontoyago/pulumi-gcp-bootstrap/coverage.html) [![Go Reference](https://pkg.go.dev/badge/github.com/davidmontoyago/pulumi-gcp-bootstrap.svg)](https://pkg.go.dev/github.com/davidmontoyago/pulumi-gcp-bootstrap)

Day 1 infra for GCP.

- **State Buckets** for Pulumi state and Terraform state files
- **Audit Logging** with security and audit log sinks, lifecycle and default retention
- **Organization Policies** to require HTTPS, restrict public bucket access, uniform level access, etc
- **IAM Policies** access controls for personas `infrastructure-team`, `security-team`, `compliance-team`, `soc-team`

## Prerequisites

1. [Go 1.24+](https://golang.org/dl/)
2. [Pulumi CLI](https://pulumi.io/quickstart/install.html)
3. [gcloud CLI](https://cloud.google.com/sdk/gcloud/) configured with appropriate permissions

## Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/davidmontoyago/pulumi-gcp-bootstrap
cd pulumi-gcp-bootstrap
make pre-reqs
```

### 2. Configure Environment

Set the required environment variables:

| Variable                      | Required | Default               | Description                    |
| ----------------------------- | -------- | --------------------- | ------------------------------ |
| `GCP_PROJECT`                 | ✅        | -                     | Your GCP Project ID            |
| `GCP_REGION`                  | ❌        | `us-central1`         | GCP Region for resources       |
| `KMS_KEY_ROTATION_PERIOD`     | ❌        | `2592000s`            | Key rotation period (30 days)  |
| `STATE_STORAGE_PREFIX`        | ❌        | `infra-state`         | Prefix for state bucket naming |
| `RETENTION_PERIOD_DAYS`       | ❌        | `365`                 | Bucket retention period        |
| `UNIFORM_BUCKET_LEVEL_ACCESS` | ❌        | `true`                | Enable uniform bucket access   |
| `PUBLIC_ACCESS_PREVENTION`    | ❌        | `enforced`            | Block public access            |
| `LOGGING_DESTINATION_PROJECT` | ❌        | Same as `GCP_PROJECT` | Project for logs               |
| `LOGGING_RETENTION_DAYS`      | ❌        | `30`                  | Log retention period           |
| `ENVIRONMENT`                 | ❌        | `production`          | Environment label              |

### 3. Deploy

```bash
# Initialize Pulumi stack
pulumi stack init my-stack

# Deploy the infrastructure
pulumi up
```

## Architecture

The bootstrap infrastructure creates a comprehensive security foundation for building and running apps in the cloud:

- **Encrypted State Storage**: Customer-managed KMS encryption with automated rotation
- **Audit Infrastructure**: Dedicated logging buckets with lifecycle management
- **Security Policies**: Organization policies enforcing baseline constraints
- **Access Controls**: least-privilege access for admin and security groups

## Development

### Building and Testing

```bash
# Build the project
make build

# Run tests with coverage
make test

# Run linting
make lint

# Upgrade dependencies
make upgrade
```
