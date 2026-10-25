package main

// CLI 测试只覆盖无需真实服务面的纯参数路径（usage 错误早于任何解锁与网络）。
// 端到端旅程（init→serve→put→get→run→revoke）在演练脚本里覆盖。

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/client"
)

// TestRunUsageErrorOnMissingEnvMapping run 子命令缺少 -e 凭据映射时必须报
// usage 错误（退出码 2），且不得尝试解锁或联网。
func TestRunUsageErrorOnMissingEnvMapping(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli([]string{"run", "/bin/true"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("缺 env 映射的 run 应退出 2，得 %d（stderr=%q）", code, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("run")) {
		t.Errorf("usage 错误应提及 run 用法，stderr=%q", stderr.String())
	}
}

// TestRunUsageErrorOnMissingCommand run 有映射但没有被调用命令时同样 usage 错误。
func TestRunUsageErrorOnMissingCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli([]string{"run", "-e", "AWS_KEY=aws_access"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("无命令的 run 应退出 2，得 %d（stderr=%q）", code, stderr.String())
	}
}

// TestUsageReadsZeroWhenNoEvents 钉住 spec「样本为零报 0／不可计算」：
// 事件文件还不存在时，usage 必须给出一份诚实的空读数（rc=0），
// 而不是报错、也不是给一个估计值。
func TestUsageReadsZeroWhenNoEvents(t *testing.T) {
	t.Setenv("JINTENG_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := cli([]string{"usage"}, &stdout, &stderr); code != 0 {
		t.Fatalf("usage 退出码 = %d（stderr：%s）", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{`"numerator": 0`, `"denominator": "not-observable"`, `"ratio": null`} {
		if !strings.Contains(out, want) {
			t.Errorf("读数缺 %s：%s", want, out)
		}
	}
	if strings.Contains(out, `"criterion1_met": true`) {
		t.Error("无样本时不得判为达标")
	}
}

// TestUsageWritesEvidenceFile 校验 -out 落盘（真机读数要进证据件），权限 ≤0600。
func TestUsageWritesEvidenceFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	// 一条真实形状的成功事件（五字段）。
	ev := `{"action":"get","device_id":"dev-cli","name_blind_index":"` + strings.Repeat("a", 64) +
		`","outcome":"ok","ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ev+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "usage.json")
	var stdout, stderr bytes.Buffer
	if code := cli([]string{"usage", "-out", outPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("usage -out 退出码 = %d（stderr：%s）", code, stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读数未落盘: %v", err)
	}
	if !strings.Contains(string(data), `"device_id": "dev-cli"`) {
		t.Errorf("落盘内容不含该端读数：%s", data)
	}
	if st, err := os.Stat(outPath); err != nil || st.Mode().Perm()&^0600 != 0 {
		t.Errorf("读数文件权限 = %v，期望 ≤0600", st.Mode())
	}
}

// TestUsageRejectsExtraArgs 用法错误必须发生在任何读数之前（退出码 2）。
func TestUsageRejectsExtraArgs(t *testing.T) {
	t.Setenv("JINTENG_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := cli([]string{"usage", "extra"}, &stdout, &stderr); code != 2 {
		t.Fatalf("多余参数应得退出码 2，得 %d", code)
	}
}

// TestGetExitCode7WhenUnreachable 退出码 7 是 CLI 契约的一部分：脚本与
// 检测脚本都按它判「服务端不可达」，不得与一般操作失败（1）混为一谈。
func TestGetExitCode7WhenUnreachable(t *testing.T) {
	t.Setenv("JINTENG_DIR", t.TempDir())
	if code := exitOf(client.ErrUnreachable); code != 7 {
		t.Errorf("ErrUnreachable 应映射退出码 7，得 %d", code)
	}
	if code := exitOf(fmt.Errorf("%w: 请求发不出", client.ErrUnreachable)); code != 7 {
		t.Errorf("包装后仍须映射 7，得 %d", code)
	}
}

// TestDeleteUsageErrors：delete 的参数面必须在解锁与联网之前拒绝，
// usage 文本必须列出 delete <name>。
func TestDeleteUsageErrors(t *testing.T) {
	t.Setenv("JINTENG_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := cli([]string{"delete"}, &stdout, &stderr); code != 2 {
		t.Fatalf("缺少 name 应得退出码 2，得 %d", code)
	}
	if !strings.Contains(stderr.String(), "用法: jinteng delete <name>") {
		t.Errorf("delete usage 错误文本 = %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := cli([]string{"delete", "a", "b"}, &stdout, &stderr); code != 2 {
		t.Fatalf("多余参数应得退出码 2，得 %d", code)
	}
}

// TestUsageTextMentionsDelete：顶层 usage 必须列出 delete 命令。
func TestUsageTextMentionsDelete(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("空命令应得退出码 2，得 %d", code)
	}
	if !strings.Contains(stderr.String(), "delete <name>") {
		t.Errorf("顶层 usage 未列出 delete <name>：%q", stderr.String())
	}
}

// TestDeleteNotFoundExitCode：未找到必须映射到既有退出码 3。
func TestDeleteNotFoundExitCode(t *testing.T) {
	if code := exitOf(client.ErrNotFound); code != 3 {
		t.Errorf("ErrNotFound 应映射退出码 3，得 %d", code)
	}
}
