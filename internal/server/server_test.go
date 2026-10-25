package server

// 本文件全部凭据值为合成明文，材料只落 t.TempDir()（经 JINTENG_DIR 隔离），
// 绝不触碰真实 ~/.jinteng/；HTTP 面用 httptest 起真处理器，不绑真实 TLS 端口。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NinjaSln-labs/jinteng/internal/audit"
	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/store"
)

const synthPlaintext = "SYNTH-PL-4f3a-never-echoed-value"

type testEnv struct {
	ts   *httptest.Server
	st   *store.Store
	srv  *Server
	out  *bytes.Buffer    // Prepare 的证书指纹输出
	dir  string           // 本次 JINTENG_DIR
	devs map[string]v2Dev // 测试内登记的设备密钥（签名面用）
}

// newEnv 构造库路径（DBPath 取值必须来自 material 常量，不手工拼接文件名），
// 同一进程共用一个 *store.Store（bbolt 单写者锁）。
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	p, err := DBPath()
	if err != nil {
		t.Fatalf("DBPath: %v", err)
	}
	if filepath.Dir(p) != dir || filepath.Base(p) != material.ServerDBFile {
		t.Fatalf("DBPath = %q，必须为 Dir()/material.ServerDBFile", p)
	}
	st, err := store.Open(p)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	libKey, err := material.LibraryKey()
	if err != nil {
		t.Fatalf("LibraryKey: %v", err)
	}
	var out bytes.Buffer
	srv := New(st, libKey, Options{Out: &out})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, st: st, srv: srv, out: &out, dir: dir, devs: map[string]v2Dev{}}
}

// req 是 v1 时代的无签名入口；v2 一律走签名（e.v2Req）或直接写 v1 路径断言被拒。
func (e *testEnv) req(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal 请求体: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	resp, err := http.NewRequest(method, e.ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.ts.Client().Do(resp)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer got.Body.Close()
	data, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	return got.StatusCode, data
}

// errCode 解析被拒响应体，断言只含 {"error": code} 形态并返回 code。
func errCode(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("拒绝响应体应为 JSON: %v（body=%q）", err, body)
	}
	if len(m) != 1 {
		t.Fatalf("拒绝响应体只应含 error 一个键，得 %v", m)
	}
	code, _ := m["error"].(string)
	return code
}

// mustIndex 用服务端库密钥派生查找索引（HMAC 盲索引）。
func mustIndex(t *testing.T, name string) string {
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

// enroll 走 /v2/enroll：结构合法的新签名钥自证＋一次性配对码。
func (e *testEnv) enroll(t *testing.T, id string, pub []byte) (int, []byte) {
	sigPub, seed := mustSignKey(t)
	return e.enrollV2(t, id, pub, sigPub, seed, e.issueCode(t))
}

func (e *testEnv) enrollOK(t *testing.T, id string) []byte {
	t.Helper()
	pub := mustDHPub(t)
	status, body := e.enroll(t, id, pub)
	if status != http.StatusOK {
		t.Fatalf("合法注册应 200，得 %d body=%q", status, body)
	}
	return pub
}

// signerFor 取某端的签名 seed；未登记端用一把随机密钥（服务端应先判身份）。
func (e *testEnv) signerFor(t *testing.T, id string) []byte {
	t.Helper()
	if d, ok := e.devs[id]; ok {
		return d.seed
	}
	_, seed := mustSignKey(t)
	return seed
}

// put 发起写入：ciphertext 与 wraps 均为原字节，由服务层转 base64 上送。
// 调用方身份来自签名头，请求体里没有 device_id。
func (e *testEnv) put(t *testing.T, deviceID, name string, ciphertext []byte, wraps map[string][]byte) (int, []byte) {
	w := map[string]string{}
	for id, b := range wraps {
		w[id] = base64.StdEncoding.EncodeToString(b)
	}
	body, err := json.Marshal(map[string]any{
		"name":       name,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"wraps":      w,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e.v2Req(t, deviceID, e.signerFor(t, deviceID), 0, "", "POST", "/v2/secret", body)
}

func (e *testEnv) take(t *testing.T, name, deviceID string) (int, []byte) {
	return e.v2Req(t, deviceID, e.signerFor(t, deviceID), 0, "", "GET", "/v2/secret/"+name, nil)
}

func (e *testEnv) del(t *testing.T, name, deviceID string) (int, []byte) {
	return e.v2Req(t, deviceID, e.signerFor(t, deviceID), 0, "", "DELETE", "/v2/secret/"+name, nil)
}

func (e *testEnv) revoke(t *testing.T, deviceID string) (int, []byte) {
	body, _ := json.Marshal(map[string]any{"device_id": deviceID})
	caller := deviceID
	if _, ok := e.devs[caller]; !ok {
		for id := range e.devs {
			caller = id
			break
		}
	}
	return e.v2Req(t, caller, e.signerFor(t, caller), 0, "", "POST", "/v2/device/revoke", body)
}

// synthSecret 生成 DEK 并封存合成明文，另为该端 wrap。
func synthSecret(t *testing.T, pub []byte) (dek, ciphertext, wrap []byte) {
	t.Helper()
	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err = crypto.SealValue(dek, []byte(synthPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	wrap, err = crypto.WrapDEK(dek, pub)
	if err != nil {
		t.Fatal(err)
	}
	return dek, ciphertext, wrap
}

// TestTakeUnknownSecretGives404 三类拒绝之一：凭据名不存在 ⇒ 404 not-found。
func TestTakeUnknownSecretGives404(t *testing.T) {
	e := newEnv(t)
	e.enrollOK(t, "dev-a")
	status, body := e.take(t, "MISSING_ONE", "dev-a")
	if status != http.StatusNotFound {
		t.Fatalf("取不存在的名应 404，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "not-found" {
		t.Errorf("错误码 = %q，期望 not-found", got)
	}
}

// TestTakeByRevokedDeviceGives403 三类拒绝之二：已撤销设备 ⇒ 403 revoked，
// 且被拒响应不回显密文或 wrap 字节。
func TestTakeByRevokedDeviceGives403(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	name := "AWS_KEY"
	_, ct, w := synthSecret(t, pub)
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": w}); status != http.StatusOK {
		t.Fatalf("写入应 200，得 %d body=%q", status, body)
	}
	// 对照：撤销前可取
	if status, body := e.take(t, name, "dev-a"); status != http.StatusOK {
		t.Fatalf("撤销前取用应 200，得 %d body=%q", status, body)
	}
	if status, body := e.revoke(t, "dev-a"); status != http.StatusOK {
		t.Fatalf("撤销应 200，得 %d body=%q", status, body)
	}
	status, body := e.take(t, name, "dev-a")
	if status != http.StatusForbidden {
		t.Fatalf("已撤销设备取用应 403，得 %d", status)
	}
	if got := errCode(t, body); got != "device-revoked" {
		t.Errorf("错误码 = %q，期望 device-revoked", got)
	}
	assertNoBytesLeaked(t, body, ct, w)
}

// TestEnrollRejectsDegenerateDeviceKey 全零与长度≠32B 的 devPub 都 ⇒ 400
// bad-device-key；合法公钥仍注册成功作对照。
func TestEnrollRejectsDegenerateDeviceKey(t *testing.T) {
	e := newEnv(t)
	zero := make([]byte, 32)
	status, body := e.enroll(t, "dev-zero", zero)
	if status != http.StatusBadRequest {
		t.Fatalf("全零公钥应 400，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "bad-device-key" {
		t.Errorf("全零公钥错误码 = %q，期望 bad-device-key", got)
	}
	pub, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	status, body = e.enroll(t, "dev-short", pub[:31])
	if status != http.StatusBadRequest {
		t.Fatalf("31 字节公钥应 400，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "bad-device-key" {
		t.Errorf("截断公钥错误码 = %q，期望 bad-device-key", got)
	}
	// 对照：合法公钥注册成功
	e.enrollOK(t, "dev-valid")
	if _, err := e.st.Device("dev-valid"); err != nil {
		t.Errorf("合法公钥应已注册: %v", err)
	}
}

// TestPutRejectsUnknownDeviceWrap wraps 含未注册设备 id ⇒ 400
// unknown-device，且拒绝时密文一点都没写进去。
func TestPutRejectsUnknownDeviceWrap(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	ghostPub, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	name := "DB_DSN"
	_, ct, wA := synthSecret(t, pub)
	wGhost := wrapTo(t, ghostPub) // 任意合法 wrap 字节，关键是 id 未注册
	status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": wA, "ghost-device": wGhost})
	if status != http.StatusBadRequest {
		t.Fatalf("含未注册设备 wrap 应 400，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "unknown-device" {
		t.Errorf("错误码 = %q，期望 unknown-device", got)
	}
	// 拒绝时不得写入任何密文
	if _, _, err := e.st.GetSecret(name); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("被拒的 Put 之后 GetSecret 应 ErrNotFound，得 %v", err)
	}
	// 对照：去掉未注册 id 后同样写入必须成功（拒绝只针对悬空 wrap）
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": wA}); status != http.StatusOK {
		t.Fatalf("仅含已注册设备的写入应 200，得 %d body=%q", status, body)
	}
}

// wrapTo 只为造一个格式合法的 wrap 字节串。
func wrapTo(t *testing.T, pub []byte) []byte {
	t.Helper()
	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.WrapDEK(dek, pub)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// TestServerFilesStayInsideInventory 起服务（含 TLS 材料首次生成）
// 并取用一轮后，材料目录里出现的文件必须全部 ⊆ material.Inventory()；
// TLS 两件真实落盘、私钥权限 ≤0600、stdout 只打印指纹不打印私钥。
func TestServerFilesStayInsideInventory(t *testing.T) {
	e := newEnv(t)
	if err := e.srv.Prepare(); err != nil {
		t.Fatalf("Prepare（TLS 材料生成）: %v", err)
	}
	pub := e.enrollOK(t, "dev-a")
	name := "API_TOKEN"
	_, ct, w := synthSecret(t, pub)
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": w}); status != http.StatusOK {
		t.Fatalf("写入应 200，得 %d body=%q", status, body)
	}
	if status, body := e.take(t, name, "dev-a"); status != http.StatusOK {
		t.Fatalf("取用应 200，得 %d body=%q", status, body)
	}

	entries, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := material.Inventory()
	if err != nil {
		t.Fatal(err)
	}
	inInv := map[string]bool{}
	for _, n := range inv {
		inInv[n] = true
	}
	have := map[string]bool{}
	for _, ent := range entries {
		have[ent.Name()] = true
		if !inInv[ent.Name()] {
			t.Errorf("目录里出现清单外文件 %q（Inventory=%v）", ent.Name(), inv)
		}
	}
	for _, want := range []string{material.ServerDBFile, material.EventsFile, material.ServerCertFile, material.ServerKeyFile} {
		if !have[want] {
			t.Errorf("起服务并取用一轮后目录应含 %q", want)
		}
	}
	st, err := os.Stat(filepath.Join(e.dir, material.ServerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&^0600 != 0 {
		t.Errorf("TLS 私钥权限 = %o，必须 ≤0600", st.Mode().Perm())
	}
	printed := e.out.String()
	if !strings.Contains(printed, "SHA-256") {
		t.Errorf("首次生成应在输出里打印证书指纹（SHA-256），得 %q", printed)
	}
	if strings.Contains(printed, "PRIVATE KEY") || strings.Contains(printed, "BEGIN") {
		t.Errorf("输出只允许指纹，疑似泄漏证书私钥: %q", printed)
	}
}

// assertNoBytesLeaked 断言响应体不含给定原始字节或其 base64 形态。
func assertNoBytesLeaked(t *testing.T, body []byte, raws ...[]byte) {
	t.Helper()
	for i, raw := range raws {
		b64 := base64.StdEncoding.EncodeToString(raw)
		if bytes.Contains(body, raw) || strings.Contains(string(body), b64) {
			t.Errorf("响应体回显了第 %d 段敏感字节（len=%d）", i, len(raw))
		}
	}
}

// TestResponsesNeverContainPlaintext 拿本次合成明文对每个响应体做子串断言：
// 成功与被拒响应都不得出现明文；被拒响应还不得出现密文/wrap 片段。
func TestResponsesNeverContainPlaintext(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	name := "OPENAI_KEY"
	_, ct, w := synthSecret(t, pub)
	ctB64 := base64.StdEncoding.EncodeToString(ct)

	var bodies [][]byte
	collect := func(status int, body []byte) {
		if bytes.Contains(body, []byte(synthPlaintext)) {
			t.Errorf("响应体（status=%d）出现合成明文: %q", status, body)
		}
		bodies = append(bodies, body)
	}

	status, b := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": w})
	if status != http.StatusOK {
		t.Fatalf("put 应 200: %d %q", status, b)
	}
	collect(status, b)
	status, b = e.take(t, name, "dev-a")
	if status != http.StatusOK {
		t.Fatalf("take 应 200: %d %q", status, b)
	}
	if !bytes.Contains(b, []byte(ctB64)) {
		t.Errorf("成功取用应返回密文信封（base64），body=%q", b)
	}
	collect(status, b)
	// 三类拒绝
	status, b = e.take(t, "GHOST_NAME", "dev-a")
	if status != http.StatusNotFound {
		t.Fatalf("不存在的名应 404，得 %d", status)
	}
	collect(status, b)
	assertNoBytesLeaked(t, b, ct, w)
	status, b = e.take(t, name, "never-enrolled")
	if status != http.StatusUnauthorized {
		t.Fatalf("未注册设备应 401，得 %d body=%q", status, b)
	}
	collect(status, b)
	assertNoBytesLeaked(t, b, ct, w)
	if status, b := e.revoke(t, "dev-a"); status != http.StatusOK {
		t.Fatalf("revoke 应 200: %d %q", status, b)
	}
	status, b = e.take(t, name, "dev-a")
	if status != http.StatusForbidden {
		t.Fatalf("已撤销端应 403，得 %d", status)
	}
	collect(status, b)
	assertNoBytesLeaked(t, b, ct, w)
	if len(bodies) != 5 {
		t.Errorf("应覆盖 5 个响应体，得 %d", len(bodies))
	}
}

// TestEventsCountMatchesSuccessfulTakes 每请求一条事件：成功的 get 事件数
// 必须与成功取用次数一致；事件只含白名单字段，blind index 与 BlindIndex(library.key, name)
// 一致，明文名与明文值都不进事件。
func TestEventsCountMatchesSuccessfulTakes(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	name := "AWS_KEY"
	_, ct, w := synthSecret(t, pub)
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": w}); status != http.StatusOK {
		t.Fatalf("put 应 200: %d %q", status, body)
	}
	const takes = 3
	for i := 0; i < takes; i++ {
		if status, body := e.take(t, name, "dev-a"); status != http.StatusOK {
			t.Fatalf("第 %d 次取用应 200，得 %d body=%q", i+1, status, body)
		}
	}
	// 外加一次被拒取用，验证 outcome 区分
	if status, _ := e.take(t, "NOT_THERE", "dev-a"); status != http.StatusNotFound {
		t.Fatalf("被拒取用应 404，得 %d", status)
	}

	raw, err := os.ReadFile(filepath.Join(e.dir, material.EventsFile))
	if err != nil {
		t.Fatalf("读事件文件: %v", err)
	}
	if strings.Contains(string(raw), synthPlaintext) || strings.Contains(string(raw), name) {
		t.Fatalf("事件里出现明文名或明文值")
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var okGet, deniedGet int
	wantBI, err := BlindIndex(e.srv.libKey, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("事件行不是 JSON: %v", err)
		}
		for k := range m {
			if !allowedKey(k) {
				t.Errorf("事件出现白名单外字段 %q", k)
			}
		}
		if m["action"] == "get" {
			switch m["outcome"] {
			case "ok":
				okGet++
				if m["name_blind_index"] != wantBI {
					t.Errorf("get/ok 事件 blind index = %v，期望 %v", m["name_blind_index"], wantBI)
				}
			case "denied":
				deniedGet++
			default:
				t.Errorf("未知 outcome %v", m["outcome"])
			}
		}
	}
	if okGet != takes {
		t.Errorf("成功 get 事件数 = %d，期望 %d", okGet, takes)
	}
	if deniedGet != 1 {
		t.Errorf("被拒 get 事件数 = %d，期望 1", deniedGet)
	}
}

func allowedKey(k string) bool {
	for _, f := range audit.AllowedFields() {
		if f == k {
			return true
		}
	}
	return false
}

// TestAuditFailureGives500WithoutBusinessResult 500 audit-failed 的 fail-closed
// 路径（接口事实的测试覆盖）：事件写不进去时响应
// 为 500 audit-failed 且不发业务结果。注入方式：把 events.jsonl 换成同名目录，
// audit.Write 的 OpenFile(O_WRONLY|O_APPEND) 必失败（EISDIR），不引入任何测试
// 专用钩子。同时如实断言副作用顺序：业务 store 变更先于事件写提交——put 被
// 500 时密文已落库（重试契约：put 覆盖幂等／revoke 幂等／enroll 二次报
// device-exists，见 server.go write() 注释），被 500 的 get 纯读无副作用。
func TestAuditFailureGives500WithoutBusinessResult(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	name := "AUDIT_FAIL_ONE"
	_, ct, w := synthSecret(t, pub)
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": w}); status != http.StatusOK {
		t.Fatalf("事件健康时 put 应 200，得 %d body=%q", status, body)
	}
	if status, body := e.take(t, name, "dev-a"); status != http.StatusOK {
		t.Fatalf("事件健康时 take 应 200，得 %d body=%q", status, body)
	}

	// 掐断事件出口：删掉 events.jsonl，原位放一个同名目录。
	ev := filepath.Join(e.dir, material.EventsFile)
	if err := os.Remove(ev); err != nil {
		t.Fatalf("删除事件文件: %v", err)
	}
	if err := os.Mkdir(ev, 0700); err != nil {
		t.Fatalf("构造只读事件出口: %v", err)
	}

	// get：500 audit-failed，业务结果（密文信封／wrap）一概不发。
	status, body := e.take(t, name, "dev-a")
	if status != http.StatusInternalServerError {
		t.Fatalf("事件写失败时 take 应 500，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "audit-failed" {
		t.Errorf("错误码 = %q，期望 audit-failed", got)
	}
	assertNoBytesLeaked(t, body, ct, w)

	// put：同样 500，stored 成功结果不发（errCode 已断言 body 恰含 error 一键）；
	// 但密文在事件写之前已提交——断言实况，防止后续班底按「事件先行」字面误判。
	name2 := "AUDIT_FAIL_TWO"
	status, body = e.put(t, "dev-a", name2, ct, map[string][]byte{"dev-a": w})
	if status != http.StatusInternalServerError {
		t.Fatalf("事件写失败时 put 应 500，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "audit-failed" {
		t.Errorf("错误码 = %q，期望 audit-failed", got)
	}
	if got, _, err := e.st.GetSecret(mustIndex(t, name2)); err != nil || !bytes.Equal(got, ct) {
		t.Errorf("被 500 的 put 其 store 变更应已先提交（业务变更先于事件写），得 err=%v", err)
	}

	// revoke：500 且 revoked 成功结果不发；撤销位同样先于事件写生效。
	status, body = e.revoke(t, "dev-a")
	if status != http.StatusInternalServerError {
		t.Fatalf("事件写失败时 revoke 应 500，得 %d body=%q", status, body)
	}
	if got := errCode(t, body); got != "audit-failed" {
		t.Errorf("错误码 = %q，期望 audit-failed", got)
	}
	if dev, err := e.st.Device("dev-a"); err != nil || !dev.Revoked {
		t.Errorf("被 500 的 revoke 其撤销位应已先提交，得 dev=%+v err=%v", dev, err)
	}
}

// TestPutRejectsInvalidNameAtServiceLayer 修复轮 Important 2：命名规则
// （[A-Za-z0-9_]{1,64}）过去只在客户端强制，直接打 API 能把含 '-' 或超 64
// 字符的名写进库，而本端 Take 因跑同一条正则会取不出来——「非法名必须在任何
// 写入之前拒绝」这条系统级不变量必须由服务层闭合。
func TestPutRejectsInvalidNameAtServiceLayer(t *testing.T) {
	e := newEnv(t)
	pub := e.enrollOK(t, "dev-a")
	_, ct, w := synthSecret(t, pub)

	badNames := []string{
		"bad-name",              // 含连字符
		strings.Repeat("A", 65), // 超 64 字符
		"",                      // 空名
	}
	for _, nm := range badNames {
		status, body := e.put(t, "dev-a", nm, ct, map[string][]byte{"dev-a": w})
		if status == http.StatusOK {
			t.Fatalf("非法名 %q 竟被服务层接受（应 400）", nm)
		}
		if status != http.StatusBadRequest {
			t.Errorf("非法名 %q 应 400，得 %d body=%q", nm, status, body)
			continue
		}
		if got := errCode(t, body); got != "bad-request" {
			t.Errorf("非法名 %q 错误码 = %q，期望沿用既有 bad-request", nm, got)
		}
		// 拒绝须早于任何写入：库里取不到该名的密文（空名由 store 返回校验错误，
		// 同样证明未落库；非空名应 ErrNotFound）。
		got, _, err := e.st.GetSecret(nm)
		if err == nil || len(got) != 0 {
			t.Errorf("非法名 %q 拒绝后库里不应存在，得 ct=%d err=%v", nm, len(got), err)
		}
		if nm != "" && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("非法名 %q 应为 ErrNotFound，得 err=%v", nm, err)
		}
	}

	// 对照：合法名照旧 200，证明拒绝的是命名规则而不是写入本身。
	if status, body := e.put(t, "dev-a", "GOOD_NAME", ct, map[string][]byte{"dev-a": w}); status != http.StatusOK {
		t.Fatalf("合法名应 200，得 %d body=%q", status, body)
	}
}

// TestRevokeOneDeviceKeepsOthersTaking 修复波 IMPORTANT 5：spec
// client-credential-material 的 Scenario「撤销不影响其它端」过去从未被端到端
// 验证（既有测试只验被撤端被拒，或只有 store 层字节证据）。本用例走真链路：
// enroll dev-a＋dev-b → put 双 wrap → revoke dev-a → 健康端 dev-b 取用 200
// 且真解出明文（UnwrapDEK＋OpenValue，不桩化），同时被撤端 dev-a 得 403 revoked。
func TestRevokeOneDeviceKeepsOthersTaking(t *testing.T) {
	e := newEnv(t)
	pubA, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	if status, body := e.enroll(t, "dev-a", pubA); status != http.StatusOK {
		t.Fatalf("enroll dev-a 应 200，得 %d body=%q", status, body)
	}
	if status, body := e.enroll(t, "dev-b", pubB); status != http.StatusOK {
		t.Fatalf("enroll dev-b 应 200，得 %d body=%q", status, body)
	}
	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	name := "SHARED_ONE"
	ct, err := crypto.SealValue(dek, []byte(synthPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	wA, err := crypto.WrapDEK(dek, pubA)
	if err != nil {
		t.Fatal(err)
	}
	wB, err := crypto.WrapDEK(dek, pubB)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := e.put(t, "dev-a", name, ct, map[string][]byte{"dev-a": wA, "dev-b": wB}); status != http.StatusOK {
		t.Fatalf("双 wrap 写入应 200，得 %d body=%q", status, body)
	}
	if status, body := e.revoke(t, "dev-a"); status != http.StatusOK {
		t.Fatalf("撤销 dev-a 应 200，得 %d body=%q", status, body)
	}

	// 健康端 dev-b：撤销他人之后取用仍 200，并且真能解出明文。
	status, body := e.take(t, name, "dev-b")
	if status != http.StatusOK {
		t.Fatalf("撤销 dev-a 后 dev-b 取用应 200（撤销不影响其它端），得 %d body=%q", status, body)
	}
	var got struct {
		Ciphertext string `json:"ciphertext"`
		Wrap       string `json:"wrap"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("成功取用响应体解析失败: %v（body=%q）", err, body)
	}
	gotCT, err := base64.StdEncoding.DecodeString(got.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	gotWrap, err := base64.StdEncoding.DecodeString(got.Wrap)
	if err != nil {
		t.Fatal(err)
	}
	openedDEK, err := crypto.UnwrapDEK(gotWrap, privB)
	if err != nil {
		t.Fatalf("dev-b 私钥解 wrap 失败: %v", err)
	}
	plain, err := crypto.OpenValue(openedDEK, gotCT)
	if err != nil {
		t.Fatalf("dev-b 解封密文失败: %v", err)
	}
	if string(plain) != synthPlaintext {
		t.Errorf("dev-b 解出的值不是原明文（长度 %d）", len(plain))
	}

	// 被撤端 dev-a：同一名字同一时刻得 403 revoked。
	status, body = e.take(t, name, "dev-a")
	if status != http.StatusForbidden {
		t.Fatalf("被撤端 dev-a 取用应 403，得 %d body=%q", status, body)
	}
	if code := errCode(t, body); code != "device-revoked" {
		t.Errorf("被撤端错误码 = %q，期望 device-revoked", code)
	}
}

// TestListenRejectsUnusableAddr 是 v2 改写的守卫：不再拒非回环，但仍在任何
// 磁盘写入与 bind 之前拒掉「无法确定监听身份」的地址——空 host（绑所有接口）、
// 无法解析的主机名、缺端口的写法。回环与非回环的合法地址一律放行。
func TestListenRejectsUnusableAddr(t *testing.T) {
	e := newEnv(t)
	for _, addr := range []string{":8787", "[::]:8787", "no-such-host.invalid:8787", "not-an-address"} {
		if err := parseListenAddr(addr); err == nil {
			t.Errorf("地址 %q 应被拒绝（空 host／无法解析／写法非法），竟放行", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787", "198.51.100.7:8787"} {
		if err := parseListenAddr(addr); err != nil {
			t.Errorf("地址 %q 应放行（v2 允许显式非回环绑定），得 %v", addr, err)
		}
	}
	// 被拒的地址必须发生在任何磁盘写入之前：TLS 材料一件都没生成。
	e.srv.opts.Listen = ":8787"
	if err := e.srv.Listen(); err == nil {
		t.Fatal("空 host 的 Listen 应失败")
	}
	for _, f := range []string{material.ServerCertFile, material.ServerKeyFile} {
		if _, err := os.Stat(filepath.Join(e.dir, f)); err == nil {
			t.Errorf("被拒的 Listen 不应生成 TLS 材料，目录里却有 %s", f)
		}
	}
}
