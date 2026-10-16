package fp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGetStableAcrossCalls(t *testing.T) {
	a, err := Get()
	if err != nil {
		t.Fatalf("Get 第一次调用失败: %v", err)
	}
	b, err := Get()
	if err != nil {
		t.Fatalf("Get 第二次调用失败: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("指纹长度 = %d, want 32", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatal("两次取值不相等（跨调用不稳定）")
	}
}

func TestGetFailsWhenMachineIDMissing(t *testing.T) {
	dir := t.TempDir() // 空目录：machine-id 等价物不存在
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", dir)
	got, err := Get()
	if err == nil {
		t.Fatalf("期望 error，实际返回长度 %d 的指纹（不得返回空指纹或降级值）", len(got))
	}
	if got != nil {
		t.Fatalf("失败时不得返回任何字节，实际返回长度 %d", len(got))
	}
}

func TestGetFailsWhenMachineIDEmpty(t *testing.T) {
	dir := t.TempDir()
	// 文件存在但内容为空白 ⇒ 同样必须 error，不降级。
	if err := os.WriteFile(filepath.Join(dir, "machine-id"), []byte("  \n"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", dir)
	if _, err := Get(); err == nil {
		t.Fatal("空 machine-id 必须返回 error，不得降级")
	}
}
