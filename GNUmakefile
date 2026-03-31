default: build

build:
	go build -o terraform-provider-nftables

install: build
	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/terraform-providers/nftables/0.1.0/linux_amd64
	cp terraform-provider-nftables ~/.terraform.d/plugins/registry.terraform.io/terraform-providers/nftables/0.1.0/linux_amd64/

test:
	go test ./... -timeout 30m

testacc:
	TF_ACC=1 go test ./... -v -timeout 30m

coverage:
	go test ./... -coverprofile=coverage.out -timeout 30m
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

.PHONY: build install test testacc coverage lint
