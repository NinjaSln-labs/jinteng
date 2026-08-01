.PHONY: build test tidy dist clean smoke

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/lanvault ./cmd/lanvault

tidy:
	go mod tidy

test:
	CGO_ENABLED=0 go test ./...

dist:
	bash scripts/build.sh

clean:
	rm -rf bin dist .lanvault-test

smoke: build
	bash scripts/smoke.sh
