package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/material"
)

// validRaw 返回一份字段恰为白名单五键的原始事件，
// 供各测试在合法／非法之间只做最小差异。
func validRaw() map[string]any {
	return map[string]any{
		"ts":               time.Now().UTC().Format(time.RFC3339Nano),
		"device_id":        "dev-a",
		"action":           "get",
		"outcome":          "ok",
		"name_blind_index": "bi-9f86d08188dd61",
	}
}

func eventsPath(dir string) string { return filepath.Join(dir, material.EventsFile) }

// TestWriteRejectsUnknownField 落实硬校验：白名单外键（这里是明文凭据名 name）
// 必须返回 error，且事件文件一个字节都不写；error 文本不得回显字段值。
func TestWriteRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)

	raw := validRaw()
	raw["name"] = "AWS_KEY" // 白名单外：明文凭据名
	err := WriteRaw(raw)
	if err == nil {
		t.Fatal("WriteRaw 接受了白名单外字段，期望 error")
	}
	if _, statErr := os.Stat(eventsPath(dir)); !os.IsNotExist(statErr) {
		t.Fatalf("校验失败前已落盘事件文件: %v", statErr)
	}
	if strings.Contains(err.Error(), "AWS_KEY") {
		t.Errorf("error 文本回显了字段值: %v", err)
	}

	// 缺字段同样是硬校验失败，且同样不写任何字节
	for _, missing := range []string{"ts", "device_id", "action", "outcome", "name_blind_index"} {
		raw := validRaw()
		delete(raw, missing)
		if err := WriteRaw(raw); err == nil {
			t.Errorf("WriteRaw 接受了缺失字段 %q 的事件，期望 error", missing)
		}
	}
	if _, statErr := os.Stat(eventsPath(dir)); !os.IsNotExist(statErr) {
		t.Fatal("存在被拒绝的写入落盘")
	}
}

// TestEventHasNoPlaintextFields 校验 Event 结构恰为五个白名单字段；
// 合法事件经 Write 追加为 JSONL 后，每行字段名固定为
// ts/device_id/action/outcome/name_blind_index，明文名不出现。
func TestEventHasNoPlaintextFields(t *testing.T) {
	typ := reflect.TypeOf(Event{})
	wantFields := []string{"TS", "DeviceID", "Action", "Outcome", "NameBlindIndex"}
	if typ.NumField() != len(wantFields) {
		t.Fatalf("Event 字段数 = %d，期望 %d", typ.NumField(), len(wantFields))
	}
	for i, name := range wantFields {
		if f := typ.Field(i); f.Name != name {
			t.Errorf("Event 第 %d 个字段 = %q，期望 %q", i, f.Name, name)
		}
	}

	wantAllowed := []string{"ts", "device_id", "action", "outcome", "name_blind_index"}
	got := AllowedFields()
	if len(got) != len(wantAllowed) {
		t.Fatalf("AllowedFields 数量 = %d，期望 5", len(got))
	}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	sortedWant := append([]string(nil), wantAllowed...)
	sort.Strings(sortedWant)
	if !reflect.DeepEqual(sorted, sortedWant) {
		t.Errorf("AllowedFields = %v，期望（排序后）%v", got, sortedWant)
	}

	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)

	events := []Event{
		{TS: time.Date(2026, 10, 16, 1, 2, 3, 0, time.UTC), DeviceID: "dev-a", Action: "get", Outcome: "ok", NameBlindIndex: "bi-9f86d08188dd61"},
		{TS: time.Date(2026, 10, 16, 1, 2, 4, 0, time.UTC), DeviceID: "dev-b", Action: "put", Outcome: "denied", NameBlindIndex: "bi-00112233445566"},
	}
	for _, ev := range events {
		if err := Write(ev); err != nil {
			t.Fatalf("Write(%+v): %v", ev, err)
		}
	}

	data, err := os.ReadFile(eventsPath(dir))
	if err != nil {
		t.Fatalf("读取事件文件: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != len(events) {
		t.Fatalf("JSONL 行数 = %d，期望 %d", len(lines), len(events))
	}
	wantKeys := map[string]bool{"ts": true, "device_id": true, "action": true, "outcome": true, "name_blind_index": true}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i, err)
		}
		if len(m) != 5 {
			t.Errorf("第 %d 行字段数 = %d，期望 5", i, len(m))
		}
		for k := range m {
			if !wantKeys[k] {
				t.Errorf("第 %d 行出现白名单外字段 %q", i, k)
			}
		}
		tsStr, ok := m["ts"].(string)
		if !ok {
			t.Fatalf("第 %d 行 ts 字段不是字符串: %#v", i, m["ts"])
		}
		if _, err := time.Parse(time.RFC3339Nano, tsStr); err != nil {
			t.Errorf("第 %d 行 ts %q 不是 RFC3339Nano: %v", i, tsStr, err)
		}
	}
	// 行序即写入序（追加式），最后一行对应第二个事件
	var last map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	if last["device_id"] != "dev-b" || last["name_blind_index"] != "bi-00112233445566" {
		t.Errorf("末行内容 %v，期望 dev-b 事件", last)
	}
}
