.PHONY: build clean test lint upgrade pre-reqs

build: clean
	go build ./...

test: build
	go test -v -race -count=1 -timeout=30s -coverprofile=coverage.out ./...

clean:
	go work sync
	go mod tidy
	go mod verify

clean-pulumi:
	pulumi plugin rm --all --yes
	pulumi install --reinstall

lint:
	docker run --rm -v $$(pwd):/app \
		-v $$(go env GOCACHE):/.cache/go-build -e GOCACHE=/.cache/go-build \
		-v $$(go env GOMODCACHE):/.cache/mod -e GOMODCACHE=/.cache/mod \
		-w /app \
		golangci/golangci-lint:v2.3.0 \
		golangci-lint run --fix --verbose --output.text.colors --timeout=10m

upgrade:
	go get -u ./...
	go mod tidy

pre-reqs:
	brew install pulumi
	pulumi plugin install resource gcp
