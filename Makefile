VERSION ?= dev
BINARY  = kubescape-exporter
IMAGE   = ghcr.io/bl4ko/$(BINARY)

.PHONY: build test lint docker-build clean

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test -race -v ./...

lint:
	go vet ./...

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

clean:
	rm -rf bin/
