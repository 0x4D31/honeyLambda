.PHONY: build test check lambda

CONFIG_DIR ?= examples

build:
	CGO_ENABLED=0 go build -trimpath -o bin/honeylambda ./cmd/honeylambda

test:
	go test -race -count=1 ./...
	go vet ./...

check:
	go run ./cmd/honeylambda check -config examples/config.json

# CONFIG_DIR must contain config.json and any relative response assets.
lambda:
	rm -rf dist/lambda
	mkdir -p dist/lambda/config
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -trimpath -o dist/lambda/bootstrap ./cmd/honeylambda-lambda
	cp -R "$(CONFIG_DIR)/." dist/lambda/config/
	rm -f dist/honeylambda-lambda-arm64.zip
	cd dist/lambda && zip -qr ../honeylambda-lambda-arm64.zip bootstrap config
