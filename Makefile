.PHONY: build test tidy dist clean smoke

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/jinteng ./cmd/jinteng

tidy:
	go mod tidy

test:
	CGO_ENABLED=0 go test ./...

dist:
	bash scripts/build.sh

clean:
	rm -rf bin dist .jinteng-test

smoke: build
	bash scripts/smoke.sh
