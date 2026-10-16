package usage

import (
	"strings"
	"testing"
	"time"
)

// 本文件的事件行全部是合成值；凭据名只以盲索引形式出现。

func line(ts time.Time, device, action, outcome string) string {
	idx := "00000000000000000000000000000000000000000000000000000000000000aa"
	if action == "enroll" || action == "put" || action == "revoke" {
		idx = strings.Repeat("0", 64)
	}
	return `{"action":"` + action + `","device_id":"` + device + `","name_blind_index":"` + idx +
		`","outcome":"` + outcome + `","ts":"` + ts.UTC().Format(time.RFC3339Nano) + `"}`
}

func TestWindowBoundaryThirtyDays(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	events := strings.Join([]string{
		line(now.AddDate(0, 0, -10), "dev-a", "get", "ok"),
		line(now.AddDate(0, 0, -30), "dev-b", "get", "ok"),
		line(now.AddDate(0, 0, -31), "dev-c", "get", "ok"),
	}, "\n") + "\n"
	r, err := Aggregate(strings.NewReader(events), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.DevicesWithSuccess != 2 {
		t.Errorf("窗口内成功端数 = %d，期望 2（第 31 天那次不计入）", r.DevicesWithSuccess)
	}
	if r.Criterion1Met != true {
		t.Error("两端各≥1 次时窗口达标判定应达成")
	}
	for _, d := range r.Devices {
		if d.DeviceID == "dev-c" && (d.InWindow || d.GetOK == 0) {
			t.Errorf("第 31 天的端应如实列出但不算窗口内成功，得 %+v", d)
		}
	}
}

func TestSingleDeviceNotMet(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	events := line(now.Add(-time.Hour), "dev-a", "run", "ok") + "\n"
	r, err := Aggregate(strings.NewReader(events), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.Criterion1Met {
		t.Error("仅一端真实取用时窗口达标判定不得判达成")
	}
	if !strings.Contains(r.Criterion1Note, "需复核前提") {
		t.Errorf("未达成时必须如实标注需复核前提，得 %q", r.Criterion1Note)
	}
}

func TestZeroSampleReportsZero(t *testing.T) {
	r, err := Aggregate(strings.NewReader(""), time.Unix(1_800_000_000, 0), 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.NorthStar.Numerator != 0 {
		t.Errorf("无样本时分子 = %d，期望 0（不填估计值）", r.NorthStar.Numerator)
	}
	if r.NorthStar.Denominator != "not-observable" {
		t.Errorf("分母口径 = %q，期望 not-observable", r.NorthStar.Denominator)
	}
	if r.NorthStar.Ratio != nil {
		t.Errorf("样本不足时比值必须为空，得 %v", *r.NorthStar.Ratio)
	}
}

func TestDeniedNotCounted(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	events := strings.Join([]string{
		line(now.Add(-2*time.Hour), "dev-a", "get", "denied"),
		line(now.Add(-time.Hour), "dev-a", "get", "ok"),
		line(now.Add(-time.Minute), "dev-b", "get", "denied"),
	}, "\n") + "\n"
	r, err := Aggregate(strings.NewReader(events), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.DevicesWithSuccess != 1 {
		t.Errorf("denied 不得参与达成判定，端计数 = %d，期望 1", r.DevicesWithSuccess)
	}
	var devB DeviceStat
	for _, d := range r.Devices {
		if d.DeviceID == "dev-b" {
			devB = d
		}
	}
	if devB.Denied != 1 || devB.InWindow {
		t.Errorf("dev-b 应只在 denied 里出现（Denied=%d InWindow=%v）", devB.Denied, devB.InWindow)
	}
}

func TestIgnoresUnknownFields(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	good := line(now.Add(-time.Minute), "dev-a", "get", "ok")
	// 白名单外字段（有人加了 name）与缺字段的行：跳过而不是崩，也不参与计数。
	bad := `{"action":"get","device_id":"dev-z","name":"AWS_KEY","name_blind_index":"x","outcome":"ok","ts":"2026-11-20T12:00:00Z"}`
	short := `{"action":"get","device_id":"dev-y","outcome":"ok","ts":"2026-11-20T12:00:00Z"}`
	r, err := Aggregate(strings.NewReader(strings.Join([]string{good, bad, short}, "\n")+"\n"), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.DevicesWithSuccess != 1 {
		t.Errorf("端计数 = %d，期望只算合规行（1）", r.DevicesWithSuccess)
	}
	for _, d := range r.Devices {
		if d.DeviceID == "dev-z" || d.DeviceID == "dev-y" {
			t.Errorf("白名单外或缺字段的行被计入: %+v", d)
		}
	}
}

func TestFirstSuccessAtIsEarliest(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	events := strings.Join([]string{
		line(now.Add(-5*time.Hour), "dev-a", "get", "ok"),
		line(now.Add(-9*time.Hour), "dev-a", "run", "ok"),
		line(now.Add(-time.Hour), "dev-a", "get", "ok"),
	}, "\n") + "\n"
	r, err := Aggregate(strings.NewReader(events), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	d := r.Devices[0]
	// 口径：取用次数与首次成功时间都以服务端 get 为准（run 底下必有一条 get）。
	if !d.FirstSuccessAt.Equal(now.Add(-5 * time.Hour)) {
		t.Errorf("首次成功时间 = %s，期望最早那次 get（%s）", d.FirstSuccessAt, now.Add(-5*time.Hour))
	}
	if r.NorthStar.Numerator != 2 {
		t.Errorf("分子 = %d，期望 2（run 不重复计入）", r.NorthStar.Numerator)
	}
	if d.GetOK != 2 || d.RunOK != 1 {
		t.Errorf("计数不符: get=%d run=%d（期望 2/1）", d.GetOK, d.RunOK)
	}
}

// TestFiveKeyRowWithForeignKeyIgnored 白名单守卫必须真的生效：恰含五个键但其中
// 一个是白名单外的键（例如有人把 name_blind_index 写成 name）不得被计入成功——
// 多端使用统计的读数靠的就是「恰含五字段」这条契约。
func TestFiveKeyRowWithForeignKeyIgnored(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	bad := `{"action":"get","device_id":"dev-x","name":"AWS_KEY","outcome":"ok","ts":"` +
		now.Add(-time.Minute).UTC().Format(time.RFC3339Nano) + `"}`
	r, err := Aggregate(strings.NewReader(bad+"\n"), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.DevicesWithSuccess != 0 || r.NorthStar.Numerator != 0 {
		t.Errorf("白名单外键的行被计入：%+v", r)
	}
}

// TestRunUnderGetNotDoubleCounted 同机一次 run 会同时留下客户端 run 事件与服务端 get
// 事件（同一份 events.jsonl）。分子计的是「走本服务的取用次数」，以服务端 get 为准，
// run 只单列展示，不得翻倍。
func TestRunUnderGetNotDoubleCounted(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	events := strings.Join([]string{
		line(now.Add(-time.Hour), "dev-a", "get", "ok"),
		line(now.Add(-time.Hour), "dev-a", "run", "ok"),
		line(now.Add(-time.Minute), "dev-b", "get", "ok"),
	}, "\n") + "\n"
	r, err := Aggregate(strings.NewReader(events), now, 30)
	if err != nil {
		t.Fatal(err)
	}
	if r.NorthStar.Numerator != 2 {
		t.Errorf("分子 = %d，期望 2（一次 run 底下只有一次取用）", r.NorthStar.Numerator)
	}
	for _, d := range r.Devices {
		if d.DeviceID == "dev-a" && (d.GetOK != 1 || d.RunOK != 1) {
			t.Errorf("dev-a 应 get_ok=1、run_ok=1 分列，得 %+v", d)
		}
		if d.DeviceID == "dev-a" && len(d.SuccessAt) != 1 {
			t.Errorf("dev-a 窗口内成功取用时刻应 1 条，得 %d 条", len(d.SuccessAt))
		}
	}
}
