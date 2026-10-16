// Package usage 是使用统计读数的聚合面：读本机 events.jsonl 的服务端可见事件，
// 按端聚合成功次数与首次成功时间，输出窗口达标结论与使用占比的
// 分子口径。它不出网、不读凭据内容，也不替不可观测的分母发明算法。
package usage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// WindowDays 是统计窗口的天数（交付后 30 天）。
const WindowDays = 30

// DenominatorNotObservable 是使用占比分母的如实口径：改用复制粘贴这条路系统看不见。
const DenominatorNotObservable = "not-observable"

// DeviceStat 是一台端的取用记账。
type DeviceStat struct {
	DeviceID       string      `json:"device_id"`
	FirstSuccessAt time.Time   `json:"first_success_at"`
	GetOK          int         `json:"get_ok"`
	RunOK          int         `json:"run_ok"`
	Denied         int         `json:"denied"`
	InWindow       bool        `json:"in_window"`
	SuccessAt      []time.Time `json:"success_at,omitempty"`
}

// NorthStar 是使用占比的口径：分子可测、分母不可观测、比值为空。
type NorthStar struct {
	Numerator   int      `json:"numerator"`
	Denominator string   `json:"denominator"`
	Ratio       *float64 `json:"ratio"`
}

// Report 是一次读数的全部输出。
type Report struct {
	Now                time.Time    `json:"now"`
	WindowDays         int          `json:"window_days"`
	Devices            []DeviceStat `json:"devices"`
	DevicesWithSuccess int          `json:"devices_with_success"`
	Criterion1Met      bool         `json:"criterion1_met"`
	Criterion1Note     string       `json:"criterion1_note"`
	NorthStar          NorthStar    `json:"north_star"`
}

// event 是取用事件的白名单五字段（多一个键或少一个键都不计入）。
type event struct {
	TS             string `json:"ts"`
	DeviceID       string `json:"device_id"`
	Action         string `json:"action"`
	Outcome        string `json:"outcome"`
	NameBlindIndex string `json:"name_blind_index"`
}

// Aggregate 读 events.jsonl 并聚合。坏行、缺字段、带白名单外字段的行都被跳过
// （不报错也不计入），使读数面不因单行损坏而整体失效。
func Aggregate(r io.Reader, now time.Time, windowDays int) (Report, error) {
	type acc struct {
		firstOK time.Time
		getOK   int
		runOK   int
		denied  int
		all     []time.Time
	}
	byDev := map[string]*acc{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		if len(raw) != 5 {
			continue
		}
		// 逐键核对白名单。注意 `for k := range raw { switch ... default: continue }`
		// 里的 continue 只推进这个内层循环（第一次评审抓到的真 bug），必须用标志位。
		whitelisted := true
		for k := range raw {
			switch k {
			case "ts", "device_id", "action", "outcome", "name_blind_index":
			default:
				whitelisted = false
			}
		}
		if !whitelisted {
			continue
		}
		var ev event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, ev.TS)
		if err != nil || ev.DeviceID == "" {
			continue
		}
		a := byDev[ev.DeviceID]
		if a == nil {
			a = &acc{}
			byDev[ev.DeviceID] = a
		}
		switch {
		case ev.Outcome == "denied":
			a.denied++
		case ev.Outcome == "ok" && (ev.Action == "get" || ev.Action == "run"):
			// 一次 run 底下就是一次 get：本机同写一份 events.jsonl 时两条都在,
			// 跨机时只有服务端那条 get 进这份文件。取用次数（窗口内次数与使用占比
			// 的分子）一律以 get 为准,run 只单列展示,否则同机分子翻倍失真。
			if ev.Action == "get" {
				a.getOK++
				a.all = append(a.all, ts)
				if a.firstOK.IsZero() || ts.Before(a.firstOK) {
					a.firstOK = ts
				}
			} else {
				a.runOK++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("usage: 读取事件失败")
	}

	windowStart := now.AddDate(0, 0, -windowDays)
	rep := Report{Now: now.UTC(), WindowDays: windowDays}
	northStar := 0
	for id, a := range byDev {
		d := DeviceStat{DeviceID: id, Denied: a.denied, GetOK: a.getOK, RunOK: a.runOK}
		var inWin []time.Time
		for _, t := range a.all {
			if !t.Before(windowStart) {
				inWin = append(inWin, t.UTC())
			}
		}
		d.SuccessAt = inWin
		if len(inWin) > 0 && !a.firstOK.IsZero() {
			d.FirstSuccessAt = a.firstOK.UTC()
			d.InWindow = true
			northStar += len(inWin)
		}
		rep.Devices = append(rep.Devices, d)
	}
	sort.Slice(rep.Devices, func(i, j int) bool { return rep.Devices[i].DeviceID < rep.Devices[j].DeviceID })
	for _, d := range rep.Devices {
		if d.InWindow {
			rep.DevicesWithSuccess++
		}
	}
	rep.Criterion1Met = rep.DevicesWithSuccess >= 2
	if rep.Criterion1Met {
		rep.Criterion1Note = fmt.Sprintf("窗口内达标：%d 台端在 %d 天窗口内各自成功取用≥1 次",
			rep.DevicesWithSuccess, windowDays)
	} else {
		rep.Criterion1Note = fmt.Sprintf("窗口内未达标（窗口内 %d 台端有成功取用，须≥2）;"+
			"如实标注需复核前提，不得改写成「能力就绪即算达标」", rep.DevicesWithSuccess)
	}
	rep.NorthStar = NorthStar{Numerator: northStar, Denominator: DenominatorNotObservable, Ratio: nil}
	return rep, nil
}
