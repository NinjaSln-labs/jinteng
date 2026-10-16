package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/sign"
)

// v2 签名面／配对登记／设备名录的行为契约测试。

type v2Dev struct {
	dhPub  []byte
	sigPub []byte
	seed   []byte
}

func (e *testEnv) remember(id string, d v2Dev) { e.devs[id] = d }

func (e *testEnv) seedOf(t *testing.T, id string) []byte {
	t.Helper()
	d, ok := e.devs[id]
	if !ok {
		t.Fatalf("测试内未登记设备 %q", id)
	}
	return d.seed
}

// mustSignKey 产一把合成签名密钥（登记面测试输入）。
func mustSignKey(t *testing.T) (pub, seed []byte) {
	t.Helper()
	pub, seed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, seed
}

func nonceSynth(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// v2Send 以指定身份签名并发送一次请求到 baseURL。seed 为 nil ⇒ 无签名请求（拒绝面）。
func v2Send(t *testing.T, baseURL, deviceID string, seed []byte, ts int64, nonce,
	method, path string, query url.Values, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if nonce == "" {
		nonce = nonceSynth(t)
	}
	if ts == 0 {
		ts = time.Now().Unix()
	}
	req.Header.Set("X-Jinteng-Device", deviceID)
	req.Header.Set("X-Jinteng-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Jinteng-Nonce", nonce)
	if seed != nil {
		h := sign.Header{Device: deviceID, Ts: ts, Nonce: nonce}
		if err := sign.Sign(seed, &h, sign.CanonicalWithHeaders(h, method, path, query, body)); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		req.Header.Set("X-Jinteng-Sig", h.Sig)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (e *testEnv) v2Req(t *testing.T, deviceID string, seed []byte, ts int64, nonce, method, path string, body []byte) (int, []byte) {
	t.Helper()
	u, err := url.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	return v2Send(t, e.ts.URL, deviceID, seed, ts, nonce, method, u.Path, u.Query(), body)
}

// enrollV2 走 /v2/enroll：配对码授权＋新签名钥自签（「验签即验证」）。
func (e *testEnv) enrollV2(t *testing.T, id string, dhPub, sigPub, seed []byte, code string) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"device_id": id,
		"dh_pub":    base64.StdEncoding.EncodeToString(dhPub),
		"sig_pub":   base64.StdEncoding.EncodeToString(sigPub),
		"pair_code": code,
	})
	status, resp := e.v2Req(t, id, seed, 0, "", "POST", "/v2/enroll", body)
	if status == http.StatusOK && seed != nil {
		e.remember(id, v2Dev{dhPub: dhPub, sigPub: sigPub, seed: seed})
	}
	return status, resp
}

// issueCode 签发一枚配对码（默认 TTL）。
func (e *testEnv) issueCode(t *testing.T) string {
	t.Helper()
	return e.issueCodeTTL(t, DefaultPairTTL)
}

func (e *testEnv) issueCodeTTL(t *testing.T, ttl time.Duration) string {
	t.Helper()
	code, err := IssuePairCode(e.st, e.srv.libKey, ttl, io.Discard)
	if err != nil {
		t.Fatalf("IssuePairCode: %v", err)
	}
	return code
}

// newV2Device 生成一把设备密钥并登记，返回三件材料。
func (e *testEnv) newV2Device(t *testing.T, id string) v2Dev {
	t.Helper()
	dhPub, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	sigPub, seed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	st, body := e.enrollV2(t, id, dhPub, sigPub, seed, e.issueCode(t))
	if st != http.StatusOK {
		t.Fatalf("登记 %s 应 200，得 %d %q", id, st, body)
	}
	return e.devs[id]
}

// putSynthSecret 由某端写入一条合成凭据（按名录包 DEK）。
// takeAs 以指定签名密钥取用一条凭据，返回状态与该端 wrap 字节。
func (e *testEnv) takeAs(t *testing.T, deviceID string, seed []byte, name string) (int, []byte) {
	t.Helper()
	status, body := e.v2Req(t, deviceID, seed, 0, "", "GET", "/v2/secret/"+name, nil)
	var m struct {
		Ciphertext string `json:"ciphertext"`
		Wrap       string `json:"wrap"`
	}
	_ = json.Unmarshal(body, &m)
	w, _ := base64.StdEncoding.DecodeString(m.Wrap)
	return status, w
}

func (e *testEnv) putSynthSecret(t *testing.T, deviceID, name string) {
	t.Helper()
	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := crypto.SealValue(dek, []byte("SYNTH-VALUE"))
	if err != nil {
		t.Fatal(err)
	}
	wraps := map[string]string{}
	for id, d := range e.devs {
		if d.dhPub == nil {
			continue
		}
		w, err := crypto.WrapDEK(dek, d.dhPub)
		if err != nil {
			t.Fatal(err)
		}
		wraps[id] = base64.StdEncoding.EncodeToString(w)
	}
	body, _ := json.Marshal(map[string]any{"name": name,
		"ciphertext": base64.StdEncoding.EncodeToString(ct), "wraps": wraps})
	st, resp := e.v2Req(t, deviceID, e.seedOf(t, deviceID), 0, "", "POST", "/v2/secret", body)
	if st != http.StatusOK {
		t.Fatalf("put %s 应 200，得 %d %q", name, st, resp)
	}
}

// TestV2UnsignedRequestsRejected 落实 spec「未签名的请求被拒」：五个端点各打一次
// 无签名请求 ⇒ 一律被拒，响应体只含一个可区分的 error 码。
func TestV2UnsignedRequestsRejected(t *testing.T) {
	e := newEnv(t)
	e.newV2Device(t, "dev-a")

	type call struct {
		method, path string
		body         []byte
	}
	calls := []call{
		{"POST", "/v2/secret", []byte(`{"name":"SYNTH_NAME","ciphertext":"YQ==","wraps":{}}`)},
		{"GET", "/v2/secret/SYNTH_NAME", nil},
		{"GET", "/v2/devices", nil},
		{"POST", "/v2/device/revoke", []byte(`{"device_id":"dev-a"}`)},
		{"POST", "/v2/enroll", []byte(`{"device_id":"dev-z","dh_pub":"YQ==","sig_pub":"Yg==","pair_code":"nope"}`)},
	}
	for _, c := range calls {
		status, body := e.v2Req(t, "dev-a", nil, 0, "", c.method, c.path, c.body)
		if status < 400 {
			t.Errorf("无签名 %s %s 竟得 %d（%q）", c.method, c.path, status, body)
		}
		if errCode(t, body) == "" {
			t.Errorf("无签名 %s %s 的响应体缺可区分错误码：%q", c.method, c.path, body)
		}
	}
}

// TestV2SignatureRejectionClassesDistinguishable 五类拒绝各自可区分（错误码表）。
func TestV2SignatureRejectionClassesDistinguishable(t *testing.T) {
	e := newEnv(t)
	e.newV2Device(t, "dev-a")
	e.newV2Device(t, "dev-b")
	seedA := e.seedOf(t, "dev-a")

	status, body := e.v2Req(t, "dev-ghost", seedA, 0, "", "GET", "/v2/devices", nil)
	if status != http.StatusUnauthorized || errCode(t, body) != "unknown-device" {
		t.Errorf("未知设备 = %d %q，期望 401 unknown-device", status, body)
	}

	_, wrongSeed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	status, body = e.v2Req(t, "dev-a", wrongSeed, 0, "", "GET", "/v2/devices", nil)
	if status != http.StatusUnauthorized || errCode(t, body) != "bad-signature" {
		t.Errorf("签名错 = %d %q，期望 401 bad-signature", status, body)
	}

	status, body = e.v2Req(t, "dev-a", seedA, time.Now().Unix()-500, "", "GET", "/v2/devices", nil)
	if status != http.StatusUnauthorized || errCode(t, body) != "stale-request" {
		t.Errorf("时间窗超 = %d %q，期望 401 stale-request", status, body)
	}

	nonce := nonceSynth(t)
	if st, b := e.v2Req(t, "dev-a", seedA, 0, nonce, "GET", "/v2/devices", nil); st != http.StatusOK {
		t.Fatalf("首次请求应 200，得 %d %q", st, b)
	}
	status, body = e.v2Req(t, "dev-a", seedA, 0, nonce, "GET", "/v2/devices", nil)
	if status != http.StatusForbidden || errCode(t, body) != "replayed" {
		t.Errorf("重放 = %d %q，期望 403 replayed", status, body)
	}

	seedB := e.seedOf(t, "dev-b")
	if st, b := e.v2Req(t, "dev-b", seedB, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-b"}`)); st != http.StatusOK {
		t.Fatalf("自撤销应 200，得 %d %q", st, b)
	}
	status, body = e.v2Req(t, "dev-b", seedB, 0, "", "GET", "/v2/secret/SYNTH_NAME", nil)
	if status != http.StatusForbidden || errCode(t, body) != "device-revoked" {
		t.Errorf("已撤销端 = %d %q，期望 403 device-revoked", status, body)
	}
	if bytes.Contains(body, []byte("ciphertext")) {
		t.Error("被拒响应里出现了密文字段——拒绝必须早于任何密文出网")
	}
}

// TestV2ReplayRejectedAfterNewServerInstance 落实 spec「重放判定在服务端重启之后
// 仍然成立」：nonce 落库，换一个新 Server 实例（同一 store）仍判重放。
func TestV2ReplayRejectedAfterNewServerInstance(t *testing.T) {
	e := newEnv(t)
	e.newV2Device(t, "dev-a")
	seedA := e.seedOf(t, "dev-a")
	nonce := nonceSynth(t)
	if st, b := e.v2Req(t, "dev-a", seedA, 0, nonce, "GET", "/v2/devices", nil); st != http.StatusOK {
		t.Fatalf("首次应 200，得 %d %q", st, b)
	}
	restarted := New(e.st, e.srv.libKey, Options{Out: io.Discard})
	ts := httptest.NewServer(restarted.Handler())
	defer ts.Close()
	status, body := v2Send(t, ts.URL, "dev-a", seedA, 0, nonce, "GET", "/v2/devices", nil, nil)
	if status != http.StatusForbidden || errCode(t, body) != "replayed" {
		t.Errorf("重启后重放判定 = %d %q，期望 403 replayed", status, body)
	}
}

// TestV2DevicesDirectoryRequiresSignatureAndHoldsNoSecrets 名录面：未签名读不到;
// 已签名只拿到 id／撤销位／两把公钥。
func TestV2DevicesDirectoryRequiresSignatureAndHoldsNoSecrets(t *testing.T) {
	e := newEnv(t)
	dev := e.newV2Device(t, "dev-a")

	if status, _ := e.v2Req(t, "dev-a", nil, 0, "", "GET", "/v2/devices", nil); status != http.StatusUnauthorized {
		t.Errorf("未签名读名录 = %d，期望 401", status)
	}
	status, body := e.v2Req(t, "dev-a", dev.seed, 0, "", "GET", "/v2/devices", nil)
	if status != http.StatusOK {
		t.Fatalf("名录应 200，得 %d %q", status, body)
	}
	var resp struct {
		Devices []struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
			DhPub   string `json:"dh_pub"`
			SigPub  string `json:"sig_pub"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("名录响应格式: %v（%q）", err, body)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].ID != "dev-a" {
		t.Fatalf("名录内容不符: %+v", resp.Devices)
	}
	if b, _ := base64.StdEncoding.DecodeString(resp.Devices[0].DhPub); !bytes.Equal(b, dev.dhPub) {
		t.Error("名录里的加密公钥与登记值不符")
	}
	if b, _ := base64.StdEncoding.DecodeString(resp.Devices[0].SigPub); !bytes.Equal(b, dev.sigPub) {
		t.Error("名录里的签名公钥与登记值不符")
	}
	for _, leak := range []string{"ciphertext", "wrap", "name_blind_index"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Errorf("名录里出现凭据材料字段 %q", leak)
		}
	}
}

// TestV2PairCodeLifecycle 配对码防线：无码被拒、用过一次即失效、库里读不到码明文。
func TestV2PairCodeLifecycle(t *testing.T) {
	e := newEnv(t)
	dhPub := mustDHPub(t)

	// 结构合法但没带码：先验形态再消费码，因此一枚好码不会被坏请求烧掉。
	sigPub, seed := mustSignKey(t)
	status, body := e.enrollV2(t, "dev-no-code", dhPub, sigPub, seed, "")
	if status != http.StatusForbidden || errCode(t, body) != "invalid-pair-code" {
		t.Errorf("空配对码 = %d %q，期望 403 invalid-pair-code", status, body)
	}

	code := e.issueCode(t)
	if status, body = e.enrollV2(t, "dev-new", dhPub, sigPub, seed, code); status != http.StatusOK {
		t.Fatalf("持有效码登记应 200，得 %d %q", status, body)
	}
	status, body = e.enrollV2(t, "dev-second", dhPub, sigPub, seed, code)
	if status != http.StatusForbidden || errCode(t, body) != "invalid-pair-code" {
		t.Errorf("重复用码 = %d %q，期望 403 invalid-pair-code", status, body)
	}

	raw, err := os.ReadFile(filepath.Join(e.dir, material.ServerDBFile))
	if err == nil && bytes.Contains(raw, []byte(code)) {
		t.Error("配对码明文出现在库里")
	}
}

// mustDHPub 产一把合成 X25519 设备公钥（登记面测试输入）。
func mustDHPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestV2EnrollRejectsExpiredPairCode 过期码即失效（spec 场景「配对码过期即失效」）。
func TestV2EnrollRejectsExpiredPairCode(t *testing.T) {
	e := newEnv(t)
	dhPub := mustDHPub(t)
	sigPub, seed := mustSignKey(t)
	expiredCode := hex.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	if err := storePairCode(e.st, e.srv.libKey, expiredCode, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	status, body := e.enrollV2(t, "dev-late", dhPub, sigPub, seed, expiredCode)
	if status != http.StatusForbidden || errCode(t, body) != "invalid-pair-code" {
		t.Errorf("过期码 = %d %q，期望 403 invalid-pair-code", status, body)
	}
}

// TestV2ReEnrollAfterRevokeRestoresAccess 落实 spec「被撤销的端重新登记后可再次取用」,
// 且重新登记必须持一枚新的有效配对码；旧 wrap 副本仍解不开新值（不重包语义不变）。
func TestV2ReEnrollAfterRevokeRestoresAccess(t *testing.T) {
	e := newEnv(t)
	dev := e.newV2Device(t, "dev-a")
	e.putSynthSecret(t, "dev-a", "SYNTH_NAME")

	if st, b := e.v2Req(t, "dev-a", dev.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-a"}`)); st != http.StatusOK {
		t.Fatalf("自撤销应 200，得 %d %q", st, b)
	}
	if st, b := e.v2Req(t, "dev-a", dev.seed, 0, "", "GET", "/v2/secret/SYNTH_NAME", nil); st != http.StatusForbidden {
		t.Fatalf("撤销期间取用应 403，得 %d %q", st, b)
	}
	if st, b := e.enrollV2(t, "dev-a", dev.dhPub, dev.sigPub, dev.seed, ""); st != http.StatusForbidden {
		t.Fatalf("无新码重新登记应被拒，得 %d %q", st, b)
	}
	if st, b := e.enrollV2(t, "dev-a", dev.dhPub, dev.sigPub, dev.seed, e.issueCode(t)); st != http.StatusOK {
		t.Fatalf("持新码重新登记应 200，得 %d %q", st, b)
	}
	status, body := e.v2Req(t, "dev-a", dev.seed, 0, "", "GET", "/v2/secret/SYNTH_NAME", nil)
	if status != http.StatusOK {
		t.Errorf("spec 场景「被撤销的端重新登记后可再次取用」未兑现，得 %d %q", status, body)
	}
	_ = body

	// 不重包这条实质防线不因此松动：换一把加密公钥重登记后,库里那份按旧公钥包的
	// wrap 副本对本端新私钥无效（服务端照常回 ciphertext+wrap,解不出才是防线）。
	_, staleWrap := e.takeAs(t, "dev-a", dev.seed, "SYNTH_NAME")
	newDh, newPriv, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	// 换钥重登记只在「该端处于撤销态」时被允许（见 TestActiveDeviceCannotBeOverwritten），
	// 故先再撤一次，再拿新码换钥。
	if st, b := e.v2Req(t, "dev-a", dev.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-a"}`)); st != http.StatusOK {
		t.Fatalf("再次撤销应 200，得 %d %q", st, b)
	}
	if st, b := e.enrollV2(t, "dev-a", newDh, dev.sigPub, dev.seed, e.issueCode(t)); st != http.StatusOK {
		t.Fatalf("撤销态下换新公钥重登记应 200，得 %d %q", st, b)
	}
	if _, err := crypto.UnwrapDEK(staleWrap, newPriv); err == nil {
		t.Error("换新加密公钥重登记后,旧 wrap 副本仍可解开——撤销语义被打穿")
	}
}

// TestServeControlIssuesPairCodeWithLiveServer 钉住这条的运行形态：配对码的签发
// 发生在正在跑的服务进程里（bbolt 只有一个写者，第二个进程抢不到锁）。
// 管理通道＝serve 终端的一行输入，码打印到 serve 的输出。
func TestServeControlIssuesPairCodeWithLiveServer(t *testing.T) {
	e := newEnv(t)
	in, feed := io.Pipe()
	out := new(bytes.Buffer)
	ctrl := New(e.st, e.srv.libKey, Options{Out: out, In: in})
	go ctrl.handleControl(in)
	if _, err := feed.Write([]byte("pair\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(out.String(), "配对码") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	text := out.String()
	if !strings.Contains(text, "配对码") {
		t.Fatalf("serve 终端没有打印配对码：%q", text)
	}
	_, rest, ok := strings.Cut(text, "：")
	if !ok {
		t.Fatalf("打印格式不含码：%q", text)
	}
	code := strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])
	if len(code) != 32 {
		t.Fatalf("配对码长度 = %d，期望 32 位十六进制", len(code))
	}
	// 这枚码确实可用：拿它完成一次登记
	dhPub, _, _ := crypto.NewDevice()
	sigPub, seed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	if st, b := e.enrollV2(t, "dev-via-control", dhPub, sigPub, seed, code); st != http.StatusOK {
		t.Fatalf("控制通道签发的码应可用，得 %d %q", st, b)
	}
	// 列举面只出索引前缀，不出码明文
	out.Reset()
	if _, err := feed.Write([]byte("pair list\n")); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for !strings.Contains(out.String(), "配对码") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(out.String(), code) {
		t.Error("pair list 把码明文打上了屏")
	}
}

// TestActiveDeviceCannotBeOverwritten 堵住「持一枚合法码即可顶替活跃端」：
// 未撤销在册端的重登记只允许公钥逐字节不变（同端重放登记），换新公钥必须被拒。
// 否则攻击者可用合法码把某端换成自己的 dh 公钥，此后所有写入的 DEK 都包给他。
func TestActiveDeviceCannotBeOverwritten(t *testing.T) {
	e := newEnv(t)
	dev := e.newV2Device(t, "dev-a")
	newDh, _, _ := crypto.NewDevice()
	newSig, newSeed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	st, body := e.enrollV2(t, "dev-a", newDh, newSig, newSeed, e.issueCode(t))
	if st != http.StatusForbidden || errCode(t, body) != "device-exists" {
		t.Fatalf("未撤销在册端换公钥重登记应 403 device-exists，得 %d %q", st, body)
	}
	// 原端仍可正常取用（没被静默锁死）
	if st, b := e.v2Req(t, "dev-a", dev.seed, 0, "", "GET", "/v2/devices", nil); st != http.StatusOK {
		t.Fatalf("原端被顶替后失效：%d %q", st, b)
	}
}

// TestPutRejectsWrapForRevokedDevice 撤销端不得再拿到任何凭据的新 DEK 副本，
// 即便写入端的时序刚好落在「取完名录 → 落库」之间（TOCTOU）。
func TestPutRejectsWrapForRevokedDevice(t *testing.T) {
	e := newEnv(t)
	e.newV2Device(t, "dev-a")
	devB := e.newV2Device(t, "dev-b")
	if st, b := e.v2Req(t, "dev-b", devB.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-b"}`)); st != http.StatusOK {
		t.Fatalf("撤销 dev-b 应 200，得 %d %q", st, b)
	}

	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := crypto.SealValue(dek, []byte("SYNTH-VALUE"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := crypto.WrapDEK(dek, devB.dhPub)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"name": "SYNTH_NAME",
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"wraps":      map[string]string{"dev-a": base64.StdEncoding.EncodeToString(w), "dev-b": base64.StdEncoding.EncodeToString(w)}})
	st, b := e.v2Req(t, "dev-a", e.seedOf(t, "dev-a"), 0, "", "POST", "/v2/secret", body)
	if st != http.StatusBadRequest || errCode(t, b) != "revoked-device" {
		t.Fatalf("含已撤销端 wrap 的写入应 400 revoked-device，得 %d %q", st, b)
	}
	// 被拒时一个字节都不落库
	if _, _, err := e.st.GetSecret(mustIndex(t, "SYNTH_NAME")); err == nil {
		t.Error("被拒的 put 仍写入了密文")
	}
}

// TestEnrollIdentityMustMatchHeader 身份只有一个来源：请求体里的 device_id 必须与
// 被验签的签名头一致，否则「自证签名」与「登记到哪个 id」会二义。
func TestEnrollIdentityMustMatchHeader(t *testing.T) {
	e := newEnv(t)
	dhPub := mustDHPub(t)
	sigPub, seed := mustSignKey(t)
	body, _ := json.Marshal(map[string]any{
		"device_id": "dev-other",
		"dh_pub":    base64.StdEncoding.EncodeToString(dhPub),
		"sig_pub":   base64.StdEncoding.EncodeToString(sigPub),
		"pair_code": e.issueCode(t),
	})
	st, b := e.v2Req(t, "dev-claimed", seed, 0, "", "POST", "/v2/enroll", body)
	if st != http.StatusUnauthorized || errCode(t, b) != "bad-signature" {
		t.Fatalf("体侧 id 与签名头不一致应 401 bad-signature，得 %d %q", st, b)
	}
	if _, err := e.st.Device("dev-other"); err == nil {
		t.Error("身份不一致时不得产生任何在册端")
	}
}

// ── Verify 退回轮（2026-10-16）：撤销发起面／重登记锚定／登记原子性 ──

// TestRevokeForeignDeviceRejected 钉住用户 2026-10-16 裁定：客户端只能撤销自己那端，
// 撤他端一律拒绝（撤他端属服务端操作员面，走 serve 管理通道）。
func TestRevokeForeignDeviceRejected(t *testing.T) {
	e := newEnv(t)
	devA := e.newV2Device(t, "dev-a")
	devB := e.newV2Device(t, "dev-b")
	e.putSynthSecret(t, "dev-a", "SYNTH_NAME")

	st, b := e.v2Req(t, "dev-a", devA.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-b"}`))
	if st != http.StatusForbidden || errCode(t, b) != "revoke-foreign" {
		t.Fatalf("撤销他端应 403 revoke-foreign，得 %d %q", st, b)
	}
	// 目标端不受影响：仍能取到同一条凭据
	if code, _ := e.takeAs(t, "dev-b", devB.seed, "SYNTH_NAME"); code != http.StatusOK {
		t.Errorf("被攻击性撤销请求指向的端应不受影响，取用得 %d", code)
	}
	// 自撤照旧可用
	if st, b := e.v2Req(t, "dev-a", devA.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-a"}`)); st != http.StatusOK {
		t.Fatalf("自撤应 200，得 %d %q", st, b)
	}
}

// TestControlChannelRevokesAnyDevice 撤他端的正当路径＝服务端终端管理通道（与 pair 同路）。
func TestControlChannelRevokesAnyDevice(t *testing.T) {
	e := newEnv(t)
	e.newV2Device(t, "dev-a")
	devB := e.newV2Device(t, "dev-b")
	e.putSynthSecret(t, "dev-a", "SYNTH_NAME")

	in, feed := io.Pipe()
	out := new(bytes.Buffer)
	ctrl := New(e.st, e.srv.libKey, Options{Out: out, In: in})
	go ctrl.handleControl(in)
	if _, err := feed.Write([]byte("revoke dev-b\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d, err := e.st.Device("dev-b"); err == nil && d.Revoked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d, err := e.st.Device("dev-b"); err != nil || !d.Revoked {
		t.Fatalf("管理通道应能撤销任意端，得 %+v err=%v 通道输出=%q", d, err, out.String())
	}
	if code, _ := e.takeAs(t, "dev-b", devB.seed, "SYNTH_NAME"); code != http.StatusForbidden {
		t.Errorf("管理通道撤销后该端取用应 403，得 %d", code)
	}
}

// TestReEnrollAnchorsSigPub 被撤销的端重新登记时必须仍是同一把签名私钥：
// 否则「撤销他端＋换 sig_pub 重登记」可把某个 id 顶替成攻击者的身份。
// 加密公钥允许更换（密钥轮换），签名公钥不得更换。
func TestReEnrollAnchorsSigPub(t *testing.T) {
	e := newEnv(t)
	dev := e.newV2Device(t, "dev-a")
	if st, b := e.v2Req(t, "dev-a", dev.seed, 0, "", "POST", "/v2/device/revoke",
		[]byte(`{"device_id":"dev-a"}`)); st != http.StatusOK {
		t.Fatalf("自撤应 200，得 %d %q", st, b)
	}
	newSig, newSeed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	st, b := e.enrollV2(t, "dev-a", dev.dhPub, newSig, newSeed, e.issueCode(t))
	if st != http.StatusForbidden || errCode(t, b) != "device-exists" {
		t.Fatalf("撤销态下换签名公钥重登记应 403 device-exists，得 %d %q", st, b)
	}
	// 同一把签名公钥、换加密公钥（轮换场景）仍可重登记
	newDh, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	if st, b := e.enrollV2(t, "dev-a", newDh, dev.sigPub, dev.seed, e.issueCode(t)); st != http.StatusOK {
		t.Fatalf("同签名公钥＋新加密公钥重登记应 200，得 %d %q", st, b)
	}
}

// TestConcurrentEnrollSameIDKeepsWinner 登记面必须整体原子：闸→消费码→落库在同一条写
// 事务里。并发下同一 id 的两个登记只能一个成立，另一个既不得覆写赢家的公钥，
// 也不得烧掉自己的配对码。
func TestConcurrentEnrollSameIDKeepsWinner(t *testing.T) {
	e := newEnv(t)
	dh1, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	sig1, seed1, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	dh2, _, err := crypto.NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	sig2, seed2, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	code1, code2 := e.issueCode(t), e.issueCode(t)

	type cand struct {
		dh, sig, seed []byte
		code          string
		st            int
		idx           int
	}
	var wg sync.WaitGroup
	cands := []*cand{{dh: dh1, sig: sig1, seed: seed1, code: code1, idx: 0}, {dh: dh2, sig: sig2, seed: seed2, code: code2, idx: 1}}
	for _, c := range cands {
		wg.Add(1)
		go func(c *cand) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{
				"device_id": "dev-x", "pair_code": c.code,
				"dh_pub":  base64.StdEncoding.EncodeToString(c.dh),
				"sig_pub": base64.StdEncoding.EncodeToString(c.sig),
			})
			st, _ := e.v2Req(t, "dev-x", c.seed, 0, "", "POST", "/v2/enroll", body)
			c.st = st
		}(c)
	}
	wg.Wait()
	out := []int{cands[0].st, cands[1].st}

	ok := []*cand{}
	for _, c := range cands {
		if c.st == http.StatusOK {
			ok = append(ok, c)
		}
	}
	if len(ok) != 1 {
		t.Fatalf("同一 id 的并发登记应只有一个成功，得 %d 个（状态码 %v）", len(ok), out)
	}
	dev, err := e.st.Device("dev-x")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dev.SigPub, ok[0].sig) || !bytes.Equal(dev.DhPub, ok[0].dh) {
		t.Error("落败的登记覆写了赢家的公钥——顶替闸不在写事务内")
	}
	// 落败者的码不应被烧掉：拿它登记另一台端应成功
	loser := 1 - ok[0].idx
	st2, b2 := e.enrollV2(t, "dev-y", cands[loser].dh, cands[loser].sig, cands[loser].seed, cands[loser].code)
	if st2 != http.StatusOK {
		t.Errorf("落败请求的配对码应仍未消费，用于新端登记得 %d %q", st2, b2)
	}
}
