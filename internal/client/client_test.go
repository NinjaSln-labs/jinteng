package client

// 客户端面测试。凭据值／口令全部为合成值；材料只落 t.TempDir()
// （经 JINTENG_DIR 隔离），绝不触碰真实 ~/.jinteng/；服务面经 httptest TLS
// 服务器（127.0.0.1，真证书链＋真指纹 pinning），不绑非回环地址。

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/server"
	"github.com/NinjaSln-labs/jinteng/internal/sign"
	"github.com/NinjaSln-labs/jinteng/internal/store"
)

const testPass = "SYNTH-PASS-never-persisted-9c1b"

// env 承载一个进程内 TLS 服务面＋隔离材料目录。
type env struct {
	dir     string // JINTENG_DIR
	baseURL string
	pin     string // sha256(cert DER) hex，客户端 pinning 用
	hc      *http.Client
	ts      *httptest.Server
	st      *store.Store // bbolt 单写者锁：全测试共用这一把 handle，不再二次 Open
	libKey  []byte       // 服务端库密钥（签发配对码用）
	seeds   map[string][]byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	// 事件与库落同一 JINTENG_DIR，指纹走 machine-id 覆录钩子，绝不影响真实主目录。
	fp := fpOverride(t, "machine-alpha")
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", fp)

	p, err := server.DBPath()
	if err != nil {
		t.Fatalf("DBPath: %v", err)
	}
	st, err := store.Open(p)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	libKey, err := material.LibraryKey()
	if err != nil {
		t.Fatalf("LibraryKey: %v", err)
	}
	var out bytes.Buffer
	srv := server.New(st, libKey, server.Options{Out: &out})
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); st.Close() })

	sum := sha256.Sum256(ts.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	hc, err := newHTTPClient(pin)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	return &env{dir: dir, baseURL: ts.URL, pin: pin, hc: hc, ts: ts, st: st,
		libKey: libKey, seeds: map[string][]byte{}}
}

// fpOverride 造一个含 machine-id 的目录，供 JINTENG_FP_OVERRIDE_DIR 使用。
func fpOverride(t *testing.T, id string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "machine-id"), []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	return d
}

// forceEnvPass 把口令来源钉死为 JINTENG_PASSENV：stdin 换成 /dev/null（非 TTY，
// 避免交互提示在实现者终端挂起），PASSFILE 清空，PASSENV 设为 testPass。
func forceEnvPass(t *testing.T) {
	t.Helper()
	t.Setenv("JINTENG_PASSFILE", "")
	t.Setenv("JINTENG_PASSENV", testPass)
	noTTY(t)
}

// noTTY 把 os.Stdin 指向 /dev/null 并在测试后还原，确保 term.IsTerminal=false。
func noTTY(t *testing.T) {
	t.Helper()
	old := os.Stdin
	f, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old; f.Close() })
}

// register 用真实 v2 线格式登记一个设备：一次性配对码授权＋新签名钥自证。
// 生成的签名 seed 记在 e.seals 里，供 sealSelf 封进 device.key。
func (e *env) register(t *testing.T, id string, dhPub []byte) {
	t.Helper()
	sigPub, seed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatalf("NewSignKey: %v", err)
	}
	e.seeds[id] = seed
	code := e.issueCode(t)
	body, _ := json.Marshal(map[string]any{
		"device_id": id,
		"dh_pub":    base64.StdEncoding.EncodeToString(dhPub),
		"sig_pub":   base64.StdEncoding.EncodeToString(sigPub),
		"pair_code": code,
	})
	status, resp := e.signedReq(t, id, seed, "POST", "/v2/enroll", body)
	if status != http.StatusOK {
		t.Fatalf("enroll %s 应 200，得 %d %q", id, status, resp)
	}
}

// issueCode 在服务端侧签发一枚配对码（与 CLI pair new 同一条路径）。
func (e *env) issueCode(t *testing.T) string {
	t.Helper()
	code, err := server.IssuePairCode(e.st, e.libKey, server.DefaultPairTTL, io.Discard)
	if err != nil {
		t.Fatalf("IssuePairCode: %v", err)
	}
	return code
}

// signedReq 以某端身份签名并发一次请求（线格式管理面测试用：撤销等）。
func (e *env) signedReq(t *testing.T, id string, seed []byte, method, path string, body []byte) (int, []byte) {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	h := sign.Header{Device: id, Ts: time.Now().Unix(), Nonce: base64.StdEncoding.EncodeToString(nonce)}
	if err := sign.Sign(seed, &h, sign.CanonicalWithHeaders(h, method, path, nil, body)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, e.baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Jinteng-Device", h.Device)
	req.Header.Set("X-Jinteng-Ts", strconv.FormatInt(h.Ts, 10))
	req.Header.Set("X-Jinteng-Nonce", h.Nonce)
	req.Header.Set("X-Jinteng-Sig", h.Sig)
	resp, err := e.hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// revoke 通过 v2 线格式撤销一个设备（由另一在册端签名发起）。
func (e *env) revoke(t *testing.T, id string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"device_id": id})
	status, resp := e.signedReq(t, "dev-a", e.seeds["dev-a"], "POST", "/v2/device/revoke", body)
	if status != http.StatusOK {
		t.Fatalf("revoke %s 应 200，得 %d %q", id, status, resp)
	}
}

// writeConfig 落 client 配置（只含结构性材料：URL／pin／self id;
// v2 起没有本地注册表，绝不含凭据值或任何私钥）。
func (e *env) writeConfig(t *testing.T, deviceID string) {
	t.Helper()
	cfg := Config{ServerURL: e.baseURL, TLSPin: e.pin, DeviceID: deviceID}
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
}

// sealSelf 用口令 ‖ 当前指纹把某端「加密私钥＋登记时那把签名 seed」封进 device.key。
func (e *env) sealSelf(t *testing.T, id string, priv []byte) {
	t.Helper()
	f, err := currentFingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	seed, ok := e.seeds[id]
	if !ok {
		// 未登记端也要能封存：给它一把合成 seed（取用时由服务端拒绝）。
		_, seed, _ = crypto.NewSignKey()
	}
	blob, err := crypto.SealDeviceKeys(priv, seed, testPass, f)
	if err != nil {
		t.Fatalf("SealDeviceKeys: %v", err)
	}
	if err := material.Save(blob, 0600); err != nil {
		t.Fatalf("material.Save: %v", err)
	}
}

// makeDevice 生成一把设备密钥对。
func makeDevice(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pub, priv, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// openStore 返回服务端共用 handle 做落盘断言（仅测试用，主面仍走 HTTP）。
// 注意：bbolt 对同一文件持独占 flock，同一进程内第二次 store.Open 会死锁，
// 故断言必须复用 newEnv 已打开的 handle，而不是另开一把。
func (e *env) openStore(t *testing.T) *store.Store {
	t.Helper()
	return e.st
}

// TestUnlockWithoutPassphraseFails 2.3/异机取证口径：静息材料齐全，但无口令
// （stdin 非 TTY、PASSFILE/PASSENV 皆空）时 Unlock 必须拒绝，且错误文本不含口令。
func TestUnlockWithoutPassphraseFails(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)

	// 显式清空两个口令 env 且不 TTY。
	t.Setenv("JINTENG_PASSFILE", "")
	t.Setenv("JINTENG_PASSENV", "")
	noTTY(t)

	sess, err := Unlock()
	if err == nil {
		sess.Close()
		t.Fatal("无口令时 Unlock 必须失败")
	}
	if strings.Contains(err.Error(), testPass) {
		t.Errorf("错误文本含口令: %v", err)
	}
}

// TestUnlockFailsOnFingerprintMismatch 解锁材料绑定机器指纹：用异指纹解锁必失败。
func TestUnlockFailsOnFingerprintMismatch(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv) // 用 machine-alpha 封存

	forceEnvPass(t)
	// 换机器指纹（machine-beta）。
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", fpOverride(t, "machine-beta"))

	if _, err := Unlock(); err == nil {
		t.Fatal("指纹不匹配时 Unlock 必须失败")
	}
}

// TestUnlockSucceedsAndSessionRoundTrips 对照：同机正确口令解锁成功，put→take 往返。
func TestUnlockSucceedsAndSessionRoundTrips(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()
	if err := sess.Put("DB_DSN", "postgres://synth-value"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := sess.Take("DB_DSN")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if string(got) != "postgres://synth-value" {
		t.Errorf("Take = %q，期望原值", got)
	}
}

// TestPutRejectsInvalidName 2.3 非法输入拒绝：空串、含 '-'、超 64 字符各自报错，
// 且拒绝发生在任何写入之前（库内不出现该名）。
func TestPutRejectsInvalidName(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()

	badNames := []string{
		"",
		"has-dash",
		strings.Repeat("A", 65),
	}
	st := e.openStore(t)
	for _, nm := range badNames {
		if err := sess.Put(nm, "SYNTH-VALUE"); err == nil {
			t.Errorf("非法名 %q 应被拒绝", nm)
		}
		// 拒绝须早于任何写入：库里取不到该名的密文。注意上游 store 对空名
		// 返回的是校验错误而非 ErrNotFound（命名关口的既有行为，不改其语义），
		// 两者都证明「未落库」。
		_, _, err := st.GetSecret(nm)
		if err == nil {
			t.Errorf("非法名 %q 拒绝后库里不应存在（拒绝须早于任何写入）", nm)
		}
		if nm != "" && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("非法名 %q 应返回 ErrNotFound，得 err=%v", nm, err)
		}
	}
}

// TestPutOverwriteReplacesValue 同名二次 Put 为覆盖：Take 得新值，
// 且旧 DEK 解不出新密文（旧密文与旧 wrap 集合被整体替换）。
func TestPutOverwriteReplacesValue(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()

	name := "API_TOKEN"
	if err := sess.Put(name, "V1-old-value"); err != nil {
		t.Fatalf("Put V1: %v", err)
	}
	// 捕获旧 DEK（从旧 wrap 解出）与旧密文，供覆盖后断言。
	st := e.openStore(t)
	oldCT, oldWraps, err := st.GetSecret(mustIndexClientTest(t, name))
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	oldDEK, err := crypto.UnwrapDEK(oldWraps["dev-a"], priv)
	if err != nil {
		t.Fatalf("UnwrapDEK old: %v", err)
	}
	if old, err := crypto.OpenValue(oldDEK, oldCT); err != nil || string(old) != "V1-old-value" {
		t.Fatalf("旧 DEK 本应解出旧值，得 %q err=%v", old, err)
	}

	// 覆盖：新 DEK 重新 Seal ＋ 重新 Wrap，旧密文/旧 wrap 被整体替换。
	if err := sess.Put(name, "V2-new-value"); err != nil {
		t.Fatalf("Put V2: %v", err)
	}
	got, err := sess.Take(name)
	if err != nil {
		t.Fatalf("Take after overwrite: %v", err)
	}
	if string(got) != "V2-new-value" {
		t.Errorf("覆盖后 Take = %q，期望 V2-new-value", got)
	}

	// 断言旧 wrap 集合已被替换：库内该名的 wrap 不再是旧那条，旧 DEK 也解不开新密文。
	newCT, newWraps, err := st.GetSecret(mustIndexClientTest(t, name))
	if err != nil {
		t.Fatalf("GetSecret after overwrite: %v", err)
	}
	if bytes.Equal(newCT, oldCT) {
		t.Errorf("覆盖后密文不应与旧密文字节相同")
	}
	if _, err := crypto.OpenValue(oldDEK, newCT); err == nil {
		t.Errorf("旧 DEK 竟能解出新密文（覆盖未换 DEK？）")
	}
	if hex.EncodeToString(newWraps["dev-a"]) == hex.EncodeToString(oldWraps["dev-a"]) {
		t.Errorf("覆盖后 wrap 未被替换")
	}
}

// TestRunInjectsValueIntoChildEnv run 只注入子进程 env：真实子进程 printenv 回显合成值。
func TestRunInjectsValueIntoChildEnv(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()

	const synth = "SYNTH-INJECTED-77a1-secret-value"
	if err := sess.Put("MY_SECRET", synth); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 用真实 /usr/bin/env 子进程回显注入的变量。JINTENG_APP_TOKEN 这个变量名
	// 故意带本程序前缀：证明剔除只作用于「继承来的控制面变量」，凭据注入项照常追加。
	out := captureStdout(t, func() {
		code, err := sess.Run(map[string]string{
			"INJECTED":          "MY_SECRET",
			"JINTENG_APP_TOKEN": "MY_SECRET",
		}, []string{"/usr/bin/env"})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if code != 0 {
			t.Fatalf("Run 退出码 = %d，期望 0", code)
		}
	})
	if !strings.Contains(out, "INJECTED="+synth) {
		t.Errorf("子进程 env 未回显注入值，env 输出=\n%s", out)
	}
	if !strings.Contains(out, "JINTENG_APP_TOKEN="+synth) {
		t.Errorf("注入项不该被控制面过滤吃掉，env 输出=\n%s", out)
	}

	// 修复轮 Important 1：本程序的控制面变量绝不交给子进程——JINTENG_PASSENV 的
	// 值是解封口令本身，交出去等于让每条 `run` 的第三方命令及其衍生程序读到口令。
	for _, forbidden := range []string{
		"JINTENG_PASSENV=", "JINTENG_PASSFILE=", "JINTENG_FP_OVERRIDE_DIR=", "JINTENG_DIR=",
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("子进程 env 泄漏本程序控制面变量 %q", forbidden)
		}
	}
	// 更强的一条：口令值本身不得出现在子进程可见的任何 env 行里。
	if strings.Contains(out, testPass) {
		t.Errorf("子进程 env 含解封口令值")
	}
}

// TestRunChildExitCodePropagated 子进程退出码原样返回（Run 不吞非零退出为 error）。
func TestRunChildExitCodePropagated(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()
	// 无需注入，仍要求 Run 能用空映射跑真命令。
	code, err := sess.Run(map[string]string{}, []string{"/bin/sh", "-c", "exit 7"})
	if err != nil {
		t.Fatalf("Run 非零退出不该返回 error，得 %v", err)
	}
	if code != 7 {
		t.Errorf("Run 退出码 = %d，期望透传 7", code)
	}
}

// TestUnlockRejectsPlainHTTPServerURL 修复轮 Important 3：config.json 被手改或
// 换成坏值时，明文 http 会让 TLS pinning 整个不参与（无证书可验），凭据名与
// device id 明文上网。方案校验必须发生在 loadConfig，而不是只在 Init。
func TestUnlockRejectsPlainHTTPServerURL(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	// 真·明文 HTTP 面（同一个 handler，不带 TLS），URL 必然以 http:// 开头。
	plain := httptest.NewServer(e.ts.Config.Handler)
	t.Cleanup(plain.Close)
	if !strings.HasPrefix(plain.URL, "http://127.0.0.1") {
		t.Fatalf("前置条件：需要明文回环 URL，得 %q", plain.URL)
	}
	if err := saveConfig(Config{
		ServerURL: plain.URL, TLSPin: e.pin, DeviceID: "dev-a",
	}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	sess, err := Unlock()
	if err == nil {
		sess.Close()
		t.Fatal("config 的 server_url 是 http:// 时 Unlock 必须失败（不允许降级明文）")
	}
	if strings.Contains(err.Error(), testPass) {
		t.Errorf("错误文本含口令: %v", err)
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("错误应说明服务端 URL 必须为 https，得 %v", err)
	}
	// Init 同样不允许明文 URL（登记路径共用同一道把关，且拒绝发生在任何出网之前）。
	if err := Init(plain.URL, e.pin, "dev-a", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("http:// URL 下 Init 必须失败")
	} else if strings.Contains(err.Error(), testPass) {
		t.Errorf("Init 错误文本含口令: %v", err)
	}

	// 对照：仅方案不同（同一测试服务的 https URL）时解锁正常——拒绝的是明文，不是配置本身。
	e.writeConfig(t, "dev-a")
	httpsSess, err := Unlock()
	if err != nil {
		t.Fatalf("https 配置应可解锁: %v", err)
	}
	httpsSess.Close()
}

// TestDeviceExistsCodeMapsToRetryHint 与上一条同源（Minor 1）：device-exists 由
// responseError 按码解析，不再靠 Enroll 里的裸子串匹配，全路径共用一条映射。
func TestDeviceExistsCodeMapsToRetryHint(t *testing.T) {
	err := responseError(http.StatusBadRequest, []byte(`{"error":"device-exists"}`))
	if err == nil {
		t.Fatal("device-exists 应返回错误")
	}
	if !strings.Contains(err.Error(), "已在服务端登记") {
		t.Errorf("device-exists 应给出「已登记」重试提示，得 %v", err)
	}
	if !strings.Contains(err.Error(), "audit-failed") {
		t.Errorf("提示应说明 500 之后重试的成因，得 %v", err)
	}
}

// TestTakeErrorKindsAreDistinguishable 2.4：四类拒绝可分别用 errors.Is 判定。
// 未注册→ErrUnauthDevice、名不存在→ErrNotFound、已撤销端→ErrRevoked、
// 名存在但该端无 wrap 副本→ErrWrapMissing。
func TestTakeErrorKindsAreDistinguishable(t *testing.T) {
	e := newEnv(t)

	// --- ErrUnauthDevice：设备未在服务面登记 ---
	_, gPriv := makeDevice(t)
	e.writeConfig(t, "ghost")
	e.sealSelf(t, "ghost", gPriv)
	forceEnvPass(t)
	ghostSess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock ghost: %v", err)
	}
	_, err = ghostSess.Take("ANY_NAME")
	ghostSess.Close()
	if !errors.Is(err, ErrUnauthDevice) {
		t.Errorf("未注册设备应 ErrUnauthDevice，得 %v", err)
	}

	// --- 有效端 dev-a：ErrNotFound（名不存在）---
	aPub, aPriv := makeDevice(t)
	e.register(t, "dev-a", aPub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", aPriv)
	forceEnvPass(t)
	aSess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock dev-a: %v", err)
	}
	defer aSess.Close()
	if _, err := aSess.Take("NEVER_STORED"); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在的名应 ErrNotFound，得 %v", err)
	}

	// --- ErrRevoked：dev-a 写入后撤销自身，再取用 ---
	if err := aSess.Put("ROTATES", "v"); err != nil {
		t.Fatalf("Put ROTATES: %v", err)
	}
	e.revoke(t, "dev-a")
	if _, err := aSess.Take("ROTATES"); !errors.Is(err, ErrRevoked) {
		t.Errorf("已撤销端应 ErrRevoked，得 %v", err)
	}

	// --- ErrWrapMissing：dev-b 在写入之后才登记，对该旧名无 wrap 副本 ---
	// 重置一个干净的在册端 dev-c，先写一名；再登记 dev-b（不重包该名）；dev-b 取该名。
	cPub, cPriv := makeDevice(t)
	e.register(t, "dev-c", cPub)
	e.writeConfig(t, "dev-c")
	e.sealSelf(t, "dev-c", cPriv)
	forceEnvPass(t)
	cSess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock dev-c: %v", err)
	}
	if err := cSess.Put("PREEXISTING", "value"); err != nil {
		t.Fatalf("Put PREEXISTING: %v", err)
	}
	cSess.Close()

	bPub, bPriv := makeDevice(t)
	e.register(t, "dev-b", bPub)
	// 关键是服务面里 PREEXISTING 没有 dev-b 的 wrap 副本（它登记晚于那次写入）。
	e.writeConfig(t, "dev-b")
	e.sealSelf(t, "dev-b", bPriv)
	forceEnvPass(t)
	bSess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock dev-b: %v", err)
	}
	defer bSess.Close()
	_, err = bSess.Take("PREEXISTING")
	if !errors.Is(err, ErrWrapMissing) {
		t.Errorf("名存在但该端无 wrap 应 ErrWrapMissing（不得并入 ErrRevoked），得 %v", err)
	}
	if errors.Is(err, ErrRevoked) {
		t.Errorf("ErrWrapMissing 不得被当成 ErrRevoked")
	}
}

// TestNoCacheAfterExit 旅程零明文：完整取用旅程（put→take→run）结束后，
// 遍历 JINTENG_DIR 与工作目录，对运行期随机合成明文做子串比对，断言零命中。
func TestNoCacheAfterExit(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	// 运行期随机明文：绝不作为字面量出现在任何源文件里，扫描才有意义。
	rb := make([]byte, 24)
	if _, err := rand.Read(rb); err != nil {
		t.Fatal(err)
	}
	synth := "SYNTHNOKEY-" + hex.EncodeToString(rb)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	name := "CACHE_PROBE"
	if err := sess.Put(name, synth); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, err := sess.Take(name); err != nil || string(got) != synth {
		t.Fatalf("Take = %q err=%v", got, err)
	}
	// run 也走一次取用旅程。
	_, err = sess.Run(map[string]string{"P": name}, []string{"/bin/sh", "-c", "true"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	sess.Close()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{e.dir, cwd}
	for _, root := range roots {
		if hit := scanTreeFor(t, root, synth); hit != "" {
			t.Errorf("旅程后在 %q 树下发现明文残留: %s", root, hit)
		}
	}
}

// TestUnlockRejectsPermissivePassfile 异机取证口径实质防线：JINTENG_PASSFILE 指向
// 权限 >0600 的文件时必须拒绝并说明原因，不接受该口令来源。
func TestUnlockRejectsPermissivePassfile(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)

	pf := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(pf, []byte(testPass+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// chmod 不受 umask 影响，确保 >0600 判定确定可复现。
	if err := os.Chmod(pf, 0644); err != nil {
		t.Fatal(err)
	}
	noTTY(t)
	t.Setenv("JINTENG_PASSENV", "")
	t.Setenv("JINTENG_PASSFILE", pf)

	_, err := Unlock()
	if err == nil {
		t.Fatal("PASSFILE 权限 >0600 时 Unlock 必须拒绝")
	}
	if !strings.Contains(err.Error(), "0644") {
		t.Errorf("错误应说明权限位原因，得 %v", err)
	}

	// 对照：收紧到 0600 后同一路径应可解锁。
	if err := os.Chmod(pf, 0600); err != nil {
		t.Fatal(err)
	}
	sess, err := Unlock()
	if err != nil {
		t.Fatalf("0600 passfile 应可解锁: %v", err)
	}
	sess.Close()
}

// scanTreeFor 递归遍历 root 下的普通文件，返回首个含 needle 的文件路径（无则空串）。
func scanTreeFor(t *testing.T, root, needle string) string {
	t.Helper()
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if bytes.Contains(data, []byte(needle)) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// captureStdout 捕获 fn 执行期间写到 os.Stdout 的内容。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	out := <-done
	_ = r.Close()
	return out
}

// TestInitRejectsEmptyPassphrase 修复波 WARNING 6：空口令（TTY 直接回车或指向
// 空 passfile）绝不能通过封存——否则 device.key 降为指纹单要素，静默削弱 spec
// 「该口令与机器指纹共同生效」的两要素承诺。这里用空 passfile 构造空口令，
// 断言 Init 拒绝且一个字节都没封存。
func TestInitRejectsEmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", fpOverride(t, "machine-alpha"))
	noTTY(t)
	pf := filepath.Join(t.TempDir(), "empty.pass")
	if err := os.WriteFile(pf, []byte(""), 0600); err != nil { // 合法权限的空 passfile
		t.Fatal(err)
	}
	t.Setenv("JINTENG_PASSFILE", pf)
	t.Setenv("JINTENG_PASSENV", "")

	pin := strings.Repeat("ab", 32) // 64 位十六进制，格式合法（Init 不联网）
	err := Init("https://127.0.0.1:8787", pin, "dev-empty", strings.Repeat("0f", 16))
	if err == nil {
		t.Fatal("空口令的 Init 必须被拒绝（守住口令‖指纹双要素封存）")
	}
	if !strings.Contains(err.Error(), "空口令") {
		t.Errorf("错误应说明拒绝原因是空口令，得 %v", err)
	}
	// 拒绝须早于任何封存写入。
	for _, f := range []string{material.DeviceKeyFile, material.ConfigFile} {
		if _, serr := os.Stat(filepath.Join(dir, f)); serr == nil {
			t.Errorf("被拒的 Init 不应落任何材料，目录里却有 %s", f)
		}
	}
}

// mustIndexClientTest 与服务端同源派生盲索引（库内查找键是 HMAC 索引）。
func mustIndexClientTest(t *testing.T, name string) string {
	t.Helper()
	k, err := material.LibraryKey()
	if err != nil {
		t.Fatalf("LibraryKey: %v", err)
	}
	i, err := crypto.NameIndex(k, []byte(name))
	if err != nil {
		t.Fatalf("NameIndex: %v", err)
	}
	return i
}

// TestInitRequiresPairCode 钉住这条：登记资格来自一次性配对码。缺码必须
// 发生在任何解锁、任何封存、任何出网之前——不是「材料建好了再去登记」。
func TestInitRequiresPairCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	t.Setenv("JINTENG_FP_OVERRIDE_DIR", fpOverride(t, "machine-pair"))
	noTTY(t)
	t.Setenv("JINTENG_PASSENV", testPass)

	err := Init("https://127.0.0.1:8787", strings.Repeat("cd", 32), "dev-nocode", "")
	if err == nil || !strings.Contains(err.Error(), "配对码") {
		t.Fatalf("缺配对码的 Init 应在任何出网之前被拒，得 %v", err)
	}
	for _, f := range []string{material.DeviceKeyFile, material.ConfigFile} {
		if _, serr := os.Stat(filepath.Join(dir, f)); serr == nil {
			t.Errorf("被拒的 Init 不应落任何材料，目录里却有 %s", f)
		}
	}
}

// TestPutWrapsForServerDirectoryOnlyDevices 钉住这条闭合的缺口：写入端按
// 服务端名录重包，包括从未在写入端本地登记过的端——本地注册表已整体删除。
func TestPutWrapsForServerDirectoryOnlyDevices(t *testing.T) {
	e := newEnv(t)
	aPub, aPriv := makeDevice(t)
	e.register(t, "dev-a", aPub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", aPriv)
	forceEnvPass(t)

	// 第三端在服务面登记，但写入端的 config 里没有任何设备表可写。
	cPub, _ := makeDevice(t)
	e.register(t, "dev-c", cPub)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()
	if err := sess.Put("DIRECTORY_WRAP", "SYNTH-VALUE"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 名录里的 dev-c 必须拿到该凭据的 wrap 副本（旧实现只在本地注册表内重包，
	// 注册表外的在册端永远取不到新 DEK——此前点名的缺口）。
	_, wraps, err := e.st.GetSecret(mustIndexClientTest(t, "DIRECTORY_WRAP"))
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if _, ok := wraps["dev-c"]; !ok {
		t.Errorf("wraps 只覆盖本端可见设备（%v）——名录重包未生效", keysOf(wraps))
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, material.ConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"devices\"") {
		t.Error("config.json 里仍留着设备注册表（单一事实源应只在服务端名录）")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestUnreachableYieldsErrUnreachable 钉住这条：服务端联系不上 ⇒ 专门哨兵，
// 不给旧值、不降级（取用面唯一的「离线」出口）。
func TestUnreachableYieldsErrUnreachable(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)
	sess, err := Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	addr := dead.URL
	dead.Close() // 立刻关掉：此后任何请求都是「不可达」，不是「被拒」
	sess.cfg.ServerURL = addr
	if _, err := sess.Take("ANY_NAME"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("不可达应映射 ErrUnreachable，得 %v", err)
	}
	if err := sess.Put("ANY_NAME", "v"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("Put 同样须映射 ErrUnreachable，得 %v", err)
	}
}

// TestSessionCloseClearsBothSecrets Close 之后两把私钥都不再可用（签名能力
// 与解密能力必须同生同死）。
func TestSessionCloseClearsBothSecrets(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)
	sess, err := Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if sess.dhPriv == nil || sess.sigSeed == nil {
		t.Fatal("解锁后两把私钥都应就位")
	}
	sess.Close()
	if sess.dhPriv != nil || sess.sigSeed != nil {
		t.Error("Close 后仍有私钥引用")
	}
	if _, err := sess.Take("ANY_NAME"); err == nil {
		t.Error("Close 后的会话不得再发起签名请求")
	}
	if err := sess.Put("ANY_NAME", "v"); err == nil {
		t.Error("Close 后的会话不得再写入")
	}
}

// TestRunEventBlindIndexMatchesServerDerivation 客户端本地写的 run 事件必须与服务端
// 同一把 library.key 派生的索引逐字节相同（否则事件面按名对不上，统计失真）。
func TestRunEventBlindIndexMatchesServerDerivation(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)
	const name = "RUN_INDEX_NAME"
	sess, err := Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Put(name, "SYNTH-RUN-VALUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Run(map[string]string{"SYNTH_ENV": name}, []string{"/bin/true"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, material.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	want, err := server.BlindIndex(mustLibKeyTest(t), name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), want) {
		t.Errorf("run 事件的盲索引与服务端不同源（期望 %s，事件：%s）", want, raw)
	}
}

func mustLibKeyTest(t *testing.T) []byte {
	t.Helper()
	k, err := material.LibraryKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSessionDeleteRemovesSecret：Delete 走真实签名线格式；删除后 Take 返回
// ErrNotFound，服务端库内也读不到该索引；重复删除与非法名可区分。
func TestSessionDeleteRemovesSecret(t *testing.T) {
	e := newEnv(t)
	pub, priv := makeDevice(t)
	e.register(t, "dev-a", pub)
	e.writeConfig(t, "dev-a")
	e.sealSelf(t, "dev-a", priv)
	forceEnvPass(t)

	sess, err := Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer sess.Close()

	name := "API_TOKEN"
	if err := sess.Put(name, "V-old"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := sess.Take(name); err != nil {
		t.Fatalf("删除前 Take: %v", err)
	}
	if err := sess.Delete(name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := sess.Take(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后 Take = %v，期望 ErrNotFound", err)
	}
	if err := sess.Delete(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复 Delete = %v，期望 ErrNotFound", err)
	}
	if _, _, err := e.openStore(t).GetSecret(mustIndexClientTest(t, name)); err == nil {
		t.Error("删除后库内仍能读到该索引")
	}
	before, err := os.ReadFile(filepath.Join(e.dir, material.EventsFile))
	if err != nil {
		t.Fatalf("读事件文件: %v", err)
	}
	if err := sess.Delete("bad-name"); err == nil {
		t.Error("非法名 Delete 应在发请求前拒绝")
	}
	after, err := os.ReadFile(filepath.Join(e.dir, material.EventsFile))
	if err != nil {
		t.Fatalf("读事件文件: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("非法名 Delete 不应发请求（事件文件被追加）")
	}
}
