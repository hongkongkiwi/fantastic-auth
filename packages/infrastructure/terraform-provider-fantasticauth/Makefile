BINARY_NAME=terraform-provider-fantasticauth
VERSION=1.0.0
OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)
HOSTNAME=fantasticauth
NAMESPACE=fantasticauth
PROVIDER_NAME=fantasticauth

.PHONY: all build install test clean fmt lint docs

all: build

build:
	go build -o bin/${BINARY_NAME}

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${PROVIDER_NAME}/${VERSION}/${OS_ARCH}
	cp bin/${BINARY_NAME} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${PROVIDER_NAME}/${VERSION}/${OS_ARCH}/

test:
	go test -v ./...

testacc:
	TF_ACC=1 go test -v ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/

docs:
	tfplugindocs generate

# Local development
run:
	go run main.go

dev: install
	cd examples && terraform init -plugin-dir ~/.terraform.d/plugins

# Release builds
release:
	GOOS=darwin GOARCH=amd64 go build -o bin/${BINARY_NAME}_${VERSION}_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -o bin/${BINARY_NAME}_${VERSION}_darwin_arm64
	GOOS=linux GOARCH=amd64 go build -o bin/${BINARY_NAME}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm64 go build -o bin/${BINARY_NAME}_${VERSION}_linux_arm64
	GOOS=windows GOARCH=amd64 go build -o bin/${BINARY_NAME}_${VERSION}_windows_amd64.exe

# Dependencies
deps:
	go mod download
	go mod tidy

# Check for go module updates
update:
	go get -u ./...
	go mod tidy
