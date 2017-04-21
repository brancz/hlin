all: build

GITHUB_URL=github.com/brancz/hlin
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m)))
BIN?=hlin
COMPONENT?=cli
VERSION?=$(shell cat VERSION)

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh

compile:
	@echo ">> building $(COMPONENT) for $(GOOS)/$(GOARCH)"
	@mkdir -p _output/$(GOOS)/$(GOARCH)
	@CGO_ENABLED=0 go build --installsuffix cgo --ldflags="-s -X github.com/brancz/hlin/pkg/cli.Version=$(VERSION)" -o _output/$(GOOS)/$(GOARCH)/$(BIN) $(GITHUB_URL)/cmd/$(COMPONENT)

build: check-license compile-cli compile-api

crossbuild:
	@GOOS=darwin ARCH=amd64 $(MAKE) build
	@GOOS=linux ARCH=amd64 $(MAKE) build
	@GOOS=windows ARCH=amd64 $(MAKE) build

compile-api:
	@$(MAKE) compile COMPONENT=api BIN=hlinapi

compile-cli:
	@$(MAKE) compile COMPONENT=cli BIN=hlin

proto:
	protoc --gofast_out=plugins=grpc:. pkg/api/apipb/api.proto

.PHONY: all check-license compile build crossbuild build-api
