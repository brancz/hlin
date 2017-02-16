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

build: check-license compile

crossbuild: check-license
	@GOOS=darwin ARCH=amd64 $(MAKE) compile
	@GOOS=linux ARCH=amd64 $(MAKE) compile
	@GOOS=windows ARCH=amd64 $(MAKE) compile

.PHONY: all check-license compile build crossbuild
