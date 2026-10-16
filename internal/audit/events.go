// Package audit 提供取用事件的追加式 JSONL 写入。事件只允许白名单五字段
// TS/DeviceID/Action/Outcome/NameBlindIndex，落盘字段名固定为
// ts/device_id/action/outcome/name_blind_index；凭据名只以 blind index 形式
// 出现，明文名与凭据值绝不进事件，error 文本也不回显字段值。
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/material"
)

// Event 是一条取用事件，字段集即白名单，不多不少。
type Event struct {
	TS             time.Time
	DeviceID       string
	Action         string
	Outcome        string
	NameBlindIndex string
}

// 白名单字段名（落盘 JSON 的键）。
const (
	fieldTS             = "ts"
	fieldDeviceID       = "device_id"
	fieldAction         = "action"
	fieldOutcome        = "outcome"
	fieldNameBlindIndex = "name_blind_index"
)

// allowedSet 是白名单的单一事实源。
var allowedSet = map[string]bool{
	fieldTS:             true,
	fieldDeviceID:       true,
	fieldAction:         true,
	fieldOutcome:        true,
	fieldNameBlindIndex: true,
}

// AllowedFields 返回事件白名单的五个字段名。
func AllowedFields() []string {
	return []string{fieldTS, fieldDeviceID, fieldAction, fieldOutcome, fieldNameBlindIndex}
}

// Write 把一个 Event 追加为一行 JSONL（等价于按五字段构造后调用 WriteRaw）。
func Write(ev Event) error {
	return WriteRaw(map[string]any{
		fieldTS:             ev.TS.UTC().Format(time.RFC3339Nano),
		fieldDeviceID:       ev.DeviceID,
		fieldAction:         ev.Action,
		fieldOutcome:        ev.Outcome,
		fieldNameBlindIndex: ev.NameBlindIndex,
	})
}

// WriteRaw 是通用入口，带硬校验：出现白名单外键、或缺失任一必含字段都返回
// error，且在校验通过之前不打开文件、不写入任何字节。
//
// ponytail: 值类型未做逐字段模式校验（如 blind index 的格式）。如实说明缺口：
// server.write 只按五字段构造 Event，并不校验值形状——服务层没有这道守卫。
func WriteRaw(fields map[string]any) error {
	var unknown []string
	for k := range fields {
		if !allowedSet[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		// 只列字段名，不回显任何字段值
		return fmt.Errorf("audit: 拒绝白名单外字段: %s", strings.Join(unknown, ", "))
	}
	if len(fields) != len(allowedSet) {
		return fmt.Errorf("audit: 事件必须恰含五字段 %s", strings.Join(AllowedFields(), ", "))
	}

	// encoding/json 对 map 按键字典序输出，行内字段名与顺序确定。
	line, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("audit: 事件序列化失败: %v", err)
	}
	dir, err := material.Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("audit: 无法创建事件目录: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, material.EventsFile),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("audit: 打开事件文件失败: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: 追加事件失败: %v", err)
	}
	return nil
}
