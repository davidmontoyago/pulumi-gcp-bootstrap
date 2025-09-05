.PHONY: build deploy clean

clean:
	go work sync
	go mod tidy

build: clean
	go build -o ./build/ ./...

deploy: build
	mkdir -p .state
	pulumi login file://.state
	pulumi stack select example
	pulumi refresh
	set -a && source ./env.config && set +a && pulumi up --color=always --verbose=1 --logtostderr --stack example

undeploy:	build
	pulumi login file://.state
	pulumi stack select example
	pulumi down --color=always --verbose=1 --logtostderr --stack example
