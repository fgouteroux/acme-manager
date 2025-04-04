TEST?=$$(go list ./... |grep -v 'vendor')
GO           ?= go
GOFMT        ?= $(GO)fmt
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)
SHELL := /bin/bash
FIRST_GOPATH := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)))

clean:
	rm -rf ./build ./dist

tidy:
	go mod tidy

fmt:
	$(GOFMT) -w $(GOFMT_FILES)

lint:
	golangci-lint run

security:
	gosec -exclude=G401,G404,G505 -exclude-dir _local -quiet ./...

build:
	goreleaser build --snapshot --clean

test:
	go test -v -timeout 30s -coverprofile=cover.out -cover $(TEST)
	go tool cover -func=cover.out

release:
	goreleaser release --skip-publish --rm-dist
