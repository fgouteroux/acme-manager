TEST?=$$(go list ./... |grep -v 'vendor')
GO           ?= go
GOFMT        ?= $(GO)fmt
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)
SHELL := /bin/bash
FIRST_GOPATH := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)))
PROTOC_INCLUDES := -I. -I$(shell go list -f '{{ .Dir }}' -m github.com/gogo/protobuf)

clean:
	rm -rf ./build ./dist

tidy:
	go mod tidy

fmt:
	$(GOFMT) -w $(GOFMT_FILES)

lint:
	golangci-lint run

security:
	gosec -exclude=G401,G404,G505,G115 -exclude-dir _local -quiet ./...

build:
	goreleaser build --snapshot --clean

# Add docs generation target
docs: cmd/acme-manager-server/main.go
	swag init -g cmd/acme-manager-server/main.go -o docs --parseDependency --parseInternal

docs-fmt:
	swag fmt -g cmd/acme-manager-server/main.go

# Force docs regeneration even if files exist
docs-force:
	swag init -g cmd/acme-manager-server/main.go -o docs --parseDependency --parseInternal

test: compose-up
	rm -rf api/tests
	mkdir -p api/tests/accounts/pebble
	mkdir -p api/tests/certificates
	[ ! -f /tmp/pebble.minica.pem ] && curl -s -L -o /tmp/pebble.minica.pem https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem  && echo "pebble.minica.pem downloaded." || echo "pebble.minica.pem already exists."
	[ ! -f api/tests/accounts/pebble/private_key.pem ] && openssl ecparam -name prime256v1 -genkey -noout -out api/tests/accounts/pebble/private_key.pem && echo "private_key.pem generated." || echo "private_key.pem already exists."

	LEGO_CA_CERTIFICATES=/tmp/pebble.minica.pem go test -v -timeout 60s -coverprofile=cover.out -cover $(TEST)
	go tool cover -func=cover.out

compose-up: compose-down
	docker compose -f ./docker-compose.yml up -d
	sleep 5  # Wait for containers to initialize

compose-down:
	docker compose -f ./docker-compose.yml stop

release:
	goreleaser release --skip-publish --rm-dist

proto-clean:
	@echo "Cleaning generated protobuf files..."
	@find models -name "*.pb.go" -delete

proto: proto-clean
	@echo "Generating protobuf files..."
	@protoc $(PROTOC_INCLUDES) \
		--gogofast_out=paths=source_relative:. \
		models/*.proto
	@echo "Protobuf generation complete!"

proto-tools:
	@echo "Installing protobuf tools..."
	@go install github.com/gogo/protobuf/protoc-gen-gogofast@latest

# Declare phony targets (targets that don't create files with the same name)
.PHONY: clean tidy fmt lint security build docs docs-fmt docs-force test compose-up compose-down release proto
