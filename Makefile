all: build

GITHUB_URL=github.com/brancz/hlin
GOOS?=$(shell uname -s | tr A-Z a-z)
GOARCH?=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m)))
OUT_DIR=_output
BIN?=hlin
COMPONENT?=server
VERSION?=$(shell cat VERSION)

check-license:
	@echo ">> checking license headers"
	@./scripts/check_license.sh

compile:
	@$(eval OUTPUT=$(OUT_DIR)/$(GOOS)/$(GOARCH)/$(BIN))
	@echo ">> building $(COMPONENT) for $(GOOS)/$(GOARCH) to $(OUTPUT)"
	@mkdir -p $(OUT_DIR)/$(GOOS)/$(GOARCH)
	@CGO_ENABLED=0 go build --installsuffix cgo --ldflags="-s -X github.com/brancz/hlin/pkg/cli.Version=$(VERSION)" -o $(OUTPUT) $(GITHUB_URL)/cmd/$(COMPONENT)

build: check-license compile-server compile-client

crossbuild:
	@GOOS=darwin ARCH=amd64 $(MAKE) -s build
	@GOOS=linux ARCH=amd64 $(MAKE) -s build
	@GOOS=windows ARCH=amd64 $(MAKE) -s build

compile-server:
	@$(MAKE) -s compile COMPONENT=server BIN=hlin

compile-client:
	@$(MAKE) -s compile COMPONENT=client BIN=hlinctl

proto:
	protoc --gofast_out=plugins=grpc:. pkg/api/apipb/api.proto

devcerts:
	rm -rf $(OUT_DIR)/certs
	certstrap --depot-path "_output/certs" init --common-name "ca" --passphrase ""
	certstrap --depot-path "_output/certs" request-cert --domain mydomain.com --common-name server0 --passphrase ""
	certstrap --depot-path "_output/certs" sign --CA "ca" server0
	certstrap --depot-path "_output/certs" request-cert --domain mydomain.com --common-name server1 --passphrase ""
	certstrap --depot-path "_output/certs" sign --CA "ca" server1
	certstrap --depot-path "_output/certs" request-cert --domain mydomain.com --common-name server2 --passphrase ""
	certstrap --depot-path "_output/certs" sign --CA "ca" server2
	certstrap --depot-path "_output/certs" request-cert --ip 127.0.0.1 --common-name client --passphrase ""
	certstrap --depot-path "_output/certs" sign --CA "ca" client

.PHONY: all check-license compile build crossbuild build-api
