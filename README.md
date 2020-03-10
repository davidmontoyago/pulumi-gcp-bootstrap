# path-2-prod-go-pulumi-infra-bootstrap

### On day 0:

Scaffold Pulumi project and the **bootstrap** stack:

```sh
export PULUMI_CONFIG_PASSPHRASE=<>
export GCLOUD_PROJECT=<>
export GCLOUD_REGION=<>

pulumi login --local

pulumi new https://github.com/pulumi/templates/tree/master/gcp-go --dir ./ --force --secrets-provider passphrase --name path-2-prod-infra-bootstrap --stack bootstrap --description "Bootstraps Day 1 Infrastructure"
```

### On day 1:

Bootstrap infrastructure:

```sh
make pre-reqs

dep ensure

pulumi up
```