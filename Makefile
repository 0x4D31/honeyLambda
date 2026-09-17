.PHONY: build test check

build:
	CGO_ENABLED=0 go build -trimpath -o bin/honeylambda ./cmd/honeylambda

test:
	go test -race -count=1 ./...
	go vet ./...

check:
	go run ./cmd/honeylambda check -config examples/config.json
