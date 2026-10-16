# 金縢（jinteng）构建与演练入口。Go ≥ 1.27，全部目标不需 CGO。
# 若 go 不在 PATH：make GO=/usr/local/go/bin/go test
GO ?= go
OUT ?= bin

.PHONY: build test e2e multidev build-linux-amd64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

build:
	CGO_ENABLED=0 $(GO) build -o $(OUT)/jinteng ./cmd/jinteng

test:
	$(GO) test ./...

# 本机端到端旅程：init→put→get→run→revoke，并断言工作目录零明文落盘
e2e: build
	bash scripts/e2e-local.sh

# 多端集成演练：同机三个机器指纹值＝三个独立端，serve 绑非回环＋配对码走 serve 终端管理通道
multidev: build
	bash scripts/e2e-multidev.sh

# 分发用交叉编译（无 CGO）。各端先 uname -m 再取对应件。
build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o $(OUT)/jinteng-linux-amd64 ./cmd/jinteng
build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -o $(OUT)/jinteng-darwin-amd64 ./cmd/jinteng
build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -o $(OUT)/jinteng-darwin-arm64 ./cmd/jinteng
build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -o $(OUT)/jinteng-windows-amd64.exe ./cmd/jinteng
