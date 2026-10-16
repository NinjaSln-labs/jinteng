package sign

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

// 本文件所有密钥与请求材料均为合成值。

func mustKey(t *testing.T) (pub, seed []byte) {
	t.Helper()
	pub, seed, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, seed
}

// TestCanonicalStableAcrossQueryOrder 钉住「同一请求两端字节一致」：查询串
// 顺序不同必须派生同一签名串（否则写入端与验签端永远算不到一块儿）。
func TestCanonicalStableAcrossQueryOrder(t *testing.T) {
	q1, err := url.ParseQuery("b=2&a=1")
	if err != nil {
		t.Fatal(err)
	}
	q2, err := url.ParseQuery("a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"SYNTH_NAME"}`)
	c1 := Canonical("GET", "/v2/secret/SYNTH_NAME", q1, body)
	c2 := Canonical("GET", "/v2/secret/SYNTH_NAME", q2, body)
	if !bytes.Equal(c1, c2) {
		t.Errorf("查询顺序不同导致签名串不同:\n %q\n %q", c1, c2)
	}
	// 同 key 多值同样要稳定
	m1, _ := url.ParseQuery("k=2&k=1&j=0")
	m2, _ := url.ParseQuery("j=0&k=1&k=2")
	if !bytes.Equal(Canonical("GET", "/x", m1, nil), Canonical("GET", "/x", m2, nil)) {
		t.Error("同 key 多值未排序，签名串随顺序变化")
	}
}

// TestCanonicalCoversMethodPathQueryBody 四个分量各改一字节都必须改变签名串
// ——签名覆盖范围就是 spec「签名必须覆盖方法、路径、查询串与请求体」的落点。
func TestCanonicalCoversMethodPathQueryBody(t *testing.T) {
	base := Canonical("POST", "/v2/secret", url.Values{}, []byte("body-1"))
	if got := Canonical("GET", "/v2/secret", url.Values{}, []byte("body-1")); bytes.Equal(got, base) {
		t.Error("方法未进入签名串")
	}
	if got := Canonical("POST", "/v2/devices", url.Values{}, []byte("body-1")); bytes.Equal(got, base) {
		t.Error("路径未进入签名串")
	}
	if got := Canonical("POST", "/v2/secret", url.Values{"device": {"x"}}, []byte("body-1")); bytes.Equal(got, base) {
		t.Error("查询串未进入签名串")
	}
	if got := Canonical("POST", "/v2/secret", url.Values{}, []byte("body-2")); bytes.Equal(got, base) {
		t.Error("请求体未进入签名串")
	}
	// 空 body 与缺省必须同形（客户端与服务器都按空串处理，不留两种写法）
	if !bytes.Equal(Canonical("GET", "/p", nil, nil), Canonical("GET", "/p", url.Values{}, []byte{})) {
		t.Error("空查询/空 body 的两种写法算出不同签名串")
	}
}

// TestCheckWindowBoundaries 时间窗 ±120 s 的三个边界点各归其类（Review Focus 3）。
func TestCheckWindowBoundaries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name string
		ts   int64
		want bool
	}{
		{"-119s", now.Unix() - 119, true},
		{"-120s 恰在窗内", now.Unix() - 120, true},
		{"-121s 超窗", now.Unix() - 121, false},
		{"+120s 恰在窗内", now.Unix() + 120, true},
		{"+121s 超窗（客户端时钟快）", now.Unix() + 121, false},
	} {
		if got := CheckWindow(tc.ts, now); got != tc.want {
			t.Errorf("%s: CheckWindow=%v, 期望 %v", tc.name, got, tc.want)
		}
	}
}

// TestSignVerifyRoundTripAndTamper 验签必须能被公钥验通;签名或消息被动一个
// 字节、或换一把公钥，都必须验不通（否则「持有」这条防线是空的）。
func TestSignVerifyRoundTripAndTamper(t *testing.T) {
	pub, seed := mustKey(t)
	msg := []byte("POST\n/v2/enroll\n\ncGF5bG9hZA==")
	h := Header{Device: "dev-synth", Ts: 1_800_000_000, Nonce: "bm9uY2U="}
	if err := Sign(seed, &h, msg); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if h.Sig == "" {
		t.Fatal("Sign 未写入 Sig")
	}
	if !Verify(pub, h, msg) {
		t.Error("自端签名验不通")
	}
	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-1] ^= 0x01
	if Verify(pub, h, tampered) {
		t.Error("消息被改一字节后仍验通")
	}
	bad := h
	bad.Sig = bad.Sig[:len(bad.Sig)-2] + "AA"
	if Verify(pub, bad, msg) {
		t.Error("签名被改后仍验通")
	}
	otherPub, _ := mustKey(t)
	if Verify(otherPub, h, msg) {
		t.Error("别端公钥验通了这条签名")
	}
	if err := Sign([]byte("short"), &h, msg); err == nil {
		t.Error("seed 长度非法应返回 error")
	}
}

// TestCanonicalWithHeadersCoversIdentityTimestampNonce 钉住这条的最后一句:
// 「头三件都在签名覆盖范围内」。若 device／ts／nonce 不进签名串，攻击者截获一条
// 合法签名后只换 nonce 就能在窗口内二次使用——防重放面形同虚设。
func TestCanonicalWithHeadersCoversIdentityTimestampNonce(t *testing.T) {
	pub, seed := mustKey(t)
	body := []byte("body")
	base := Header{Device: "dev-a", Ts: 1_800_000_000, Nonce: "nonce-1"}
	full := CanonicalWithHeaders(base, "POST", "/v2/secret", nil, body)
	if err := Sign(seed, &base, full); err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, base, full) {
		t.Fatal("完整签名串验不通（客户端与服务端算的不是同一串）")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Header)
	}{
		{"换设备", func(h *Header) { h.Device = "dev-b" }},
		{"换时间戳", func(h *Header) { h.Ts++ }},
		{"换 nonce", func(h *Header) { h.Nonce = "nonce-2" }},
	} {
		mutated := base
		tc.mutate(&mutated)
		mutatedCanonical := CanonicalWithHeaders(mutated, "POST", "/v2/secret", nil, body)
		if bytes.Equal(mutatedCanonical, full) {
			t.Errorf("%s 没有改变签名串：该头不在覆盖范围内", tc.name)
			continue
		}
		if Verify(pub, mutated, mutatedCanonical) {
			t.Errorf("%s 后新串竟验通：签名与头的绑定失效", tc.name)
		}
	}
}
