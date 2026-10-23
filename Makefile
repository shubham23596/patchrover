.PHONY: build test verify demo packs site-install site-check site-build site-audit

build:
	go build -trimpath -o bin/patchrover ./cmd/patchrover

test:
	go test ./...

verify:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

demo: build
	./bin/patchrover demo

packs: build
	./bin/patchrover pack validate packs/php-2026-rce
	./bin/patchrover pack validate packs/litellm-1.107.0-compromise

site-install:
	cd site && npm ci

site-check:
	cd site && npm run check

site-build:
	cd site && npm run build

site-audit: site-build
	cd site && npm run lighthouse

