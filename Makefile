TEST?=$$(go list ./... |grep -v 'vendor')
# Container runtime used by the test fixtures. Auto-detected, preferring Docker
# when both are installed. Override with: make test COMPOSE="podman compose"
COMPOSE      ?= $(shell command -v docker >/dev/null 2>&1 && echo "docker compose" || echo "podman compose")
# Server-side debug logs during tests. Without it TestMain installs a no-op
# logger and failures surface as a bare HTTP status with no explanation.
# Quiet it with: make test ENABLE_DEBUG=false
ENABLE_DEBUG ?= true
# SELinux relabel suffix for bind mounts, auto-detected. Without it the Pebble
# mount is unreadable under Podman on SELinux hosts, and since that image is
# built FROM scratch it exits silently when it cannot read its config. Stays
# empty where SELinux is absent, so Docker behaves exactly as before.
# Force off with: make test MOUNT_LABEL=
MOUNT_LABEL  ?= $(shell (selinuxenabled 2>/dev/null || test -r /sys/fs/selinux/enforce) && echo :z)
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
	[ ! -f api/tests/accounts/pebble/private_key.pem ] && openssl ecparam -name prime256v1 -genkey -noout -out api/tests/accounts/pebble/private_key.pem && echo "private_key.pem generated." || echo "private_key.pem already exists."
	LEGO_CA_CERTIFICATES=/tmp/pebble/test/certs/pebble.minica.pem VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root ENABLE_DEBUG=$(ENABLE_DEBUG) go test -v -timeout 120s -coverprofile=cover.out -cover $(TEST)
	go tool cover -func=cover.out

compose-up: compose-down
	rm -rf /tmp/pebble
	git clone https://github.com/letsencrypt/pebble.git /tmp/pebble
	MOUNT_LABEL=$(MOUNT_LABEL) $(COMPOSE) -f ./docker-compose.yml up -d
	@echo "waiting for pebble (14000) and vault (8200)..."
	@for i in $$(seq 1 30); do \
		pebble=$$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:14000/dir 2>/dev/null || echo 000); \
		vault=$$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8200/v1/sys/health 2>/dev/null || echo 000); \
		if [ "$$pebble" = "200" ] && [ "$$vault" = "200" ]; then \
			echo "ready after $$i s (pebble=$$pebble vault=$$vault)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo ""; \
	echo "ERROR: services not ready (pebble=$$pebble vault=$$vault)"; \
	echo "--- containers ---"; MOUNT_LABEL=$(MOUNT_LABEL) $(COMPOSE) -f ./docker-compose.yml ps || true; \
	echo "--- pebble logs ---"; MOUNT_LABEL=$(MOUNT_LABEL) $(COMPOSE) -f ./docker-compose.yml logs pebble || true; \
	echo "--- vault logs ---"; MOUNT_LABEL=$(MOUNT_LABEL) $(COMPOSE) -f ./docker-compose.yml logs vault || true; \
	exit 1

compose-down:
	MOUNT_LABEL=$(MOUNT_LABEL) $(COMPOSE) -f ./docker-compose.yml stop

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
