# Kilit relay server. Every target runs from server/ with the pinned Go 1.24 toolchain
# (GOTOOLCHAIN=local: never download a newer toolchain; the deps are pinned, see README).
export GOTOOLCHAIN := local

VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: build run vet test race vectors fmt docker up down logs clean

build: ## static CGO_ENABLED=0 binary ./kilitd with the version baked in
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o kilitd ./cmd/kilitd

run: build ## local dev server (LAN clients must use the same -public-origin string)
	./kilitd -db ./dev.db -blobs ./blobs -addr :8080 -public-origin $${KILIT_PUBLIC_ORIGIN:-http://127.0.0.1:8080}

vet:
	go vet ./...

test:
	CGO_ENABLED=0 go test ./...

race: ## needs cgo + gcc
	CGO_ENABLED=1 go test -race ./...

vectors: ## regenerate test vectors; committed outputs must be unchanged
	go run ./cmd/vectors -out ../docs/vectors -swift ../ios/Kilit/Tests/Vectors

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

docker: ## image build with the same VERSION
	docker build --build-arg VERSION=$(VERSION) -t kilitd:$(VERSION) .

up: ## production: Caddy + kilitd (edit Caddyfile and KILIT_PUBLIC_ORIGIN first)
	VERSION=$(VERSION) docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100 kilitd

clean:
	rm -f kilitd
