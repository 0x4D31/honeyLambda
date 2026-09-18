.PHONY: build test check lambda

CONFIG_DIR ?= examples

build:
	CGO_ENABLED=0 go build -trimpath -o bin/honeylambda ./cmd/honeylambda

test:
	go test -race -count=1 ./...
	go vet ./...

check:
	go run ./cmd/honeylambda check -config examples/config.json

# CONFIG_DIR contains config.json; response assets are resolved by the bundler.
lambda:
	rm -rf dist/lambda
	mkdir -p dist/lambda
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -trimpath -o dist/lambda/bootstrap ./cmd/honeylambda-lambda
	go run ./cmd/honeylambda bundle -config "$(CONFIG_DIR)/config.json" -out dist/lambda/config
	rm -f dist/honeylambda-lambda-arm64.zip
	cd dist/lambda && zip -qr ../honeylambda-lambda-arm64.zip bootstrap config
