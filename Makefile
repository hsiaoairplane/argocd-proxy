.PHONY: all
all: test build

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: build
build:
	go build -o argocd-proxy -race -v .
