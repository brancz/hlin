all: build

GITHUB_URL=github.com/brancz/hlin
OS?=darwin
ARCH?=amd64
BIN?=hlin
COMPONENT?=cli

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh


compile:
	@echo ">> building $(COMPONENT) for $(OS)/$(ARCH)"
	@mkdir -p _output/$(OS)/$(ARCH)
	@CGO_ENABLED=0 go build --installsuffix cgo --ldflags="-s" -o _output/$(OS)/$(ARCH)/$(BIN) $(GITHUB_URL)/cmd/$(COMPONENT)

build: check-license compile

build-all: check-license
	@OS=darwin ARCH=amd64 $(MAKE) compile
	@OS=linux ARCH=amd64 $(MAKE) compile

.PHONY: all check-license compile build build-all
