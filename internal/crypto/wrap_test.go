package crypto

import (
	"bytes"
	"testing"
)

// 本文件所有指纹与口令均为合成值,不涉及任何真实凭据。

func synthFingerprint(seed byte) []byte {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = seed ^ byte(i)
	}
	return fp
}

// TestWrapRoundTrip 验证 wrap 信封布局 magic(4) | ephPub(32) | nonce(12) |
// ciphertext(+tag),且正确设备私钥能取回原 DEK。ephemeral 由 WrapDEK 内部生成，
// 测试只能从信封读回它。
func TestWrapRoundTrip(t *testing.T) {
	devPub, devPriv, err := NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}

	wrapped, err := WrapDEK(dek, devPub)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// 布局断言：magic(4) | ephPub(32) | nonce(12) | ciphertext+tag(32+16)
	const overhead = 4 + 32 + 12 + 16
	if len(wrapped) != overhead+len(dek) {
		t.Fatalf("wrap 长度 = %d, 期望 %d", len(wrapped), overhead+len(dek))
	}
	if !bytes.Equal(wrapped[:4], []byte{'J', 'D', 'W', '1'}) {
		t.Errorf("wrap magic = %q, 期望 %q", wrapped[:4], "JDW1")
	}
	envEph := wrapped[4:36]
	if isAllZero(envEph) {
		t.Error("envelope 的 ephPub 字段为全零")
	}
	if bytes.Equal(envEph, devPub) {
		t.Error("envelope 的 ephPub 字段等于设备公钥 ⇒ 未生成独立临时密钥对")
	}

	got, err := UnwrapDEK(wrapped, devPriv)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("UnwrapDEK 返回 %x, 期望 %x", got, dek)
	}
}

// TestUnwrapCrossDeviceFails 是本任务核心防线之一：wrap 到 A 端公钥的 DEK,
// 用另一把真实独立生成的设备私钥 B 必须解不开（而不是解出垃圾）。
func TestUnwrapCrossDeviceFails(t *testing.T) {
	devPubA, devPrivA, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	// 第二次独立密钥对生成——真实两次 NewDevice,不是拷贝也不是桩
	devPubB, devPrivB, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(devPrivA, devPrivB) || bytes.Equal(devPubA, devPubB) {
		t.Fatal("两次 NewDevice 生成了相同密钥,测试前提不成立")
	}

	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := WrapDEK(dek, devPubA)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// B 端私钥必须解不开 A 端的 wrap
	got, err := UnwrapDEK(wrapped, devPrivB)
	if err == nil {
		t.Fatalf("用 B 端私钥解开了 A 端的 wrap(返回 %d 字节),跨设备隔离失效", len(got))
	}
	if got != nil {
		t.Error("UnwrapDEK 失败时不得同时返回明文")
	}
	// 对照：A 端自己的私钥必须能解开,证明上面的失败不是 API 误用
	back, err := UnwrapDEK(wrapped, devPrivA)
	if err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("A 端自解失败: %v", err)
	}
}

// TestUnwrapTruncatedWrapFails 截断的 wrap 必须在任何解密前报错。
func TestUnwrapTruncatedWrapFails(t *testing.T) {
	devPub, devPriv, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapDEK(dek, devPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(wrapped[:len(wrapped)-1], devPriv); err == nil {
		t.Fatal("截断的 wrap 应返回 error")
	}
}

// TestWrapFreshEphemeralPerCall 钉住这条裁定：ephemeral 由 WrapDEK 内部每次新生成，
// 调用方不持有也不复用临时私钥。同一 DEK、同一设备公钥连续封装两次 ⇒ 两份信封
// 字节必须不同（临时公钥与 nonce 均重新随机），且都能用设备私钥解回同一个 DEK。
func TestWrapFreshEphemeralPerCall(t *testing.T) {
	devPub, devPriv, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}

	first, err := WrapDEK(dek, devPub)
	if err != nil {
		t.Fatalf("第一次 WrapDEK: %v", err)
	}
	second, err := WrapDEK(dek, devPub)
	if err != nil {
		t.Fatalf("第二次 WrapDEK: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("两次封装信封完全相同 ⇒ ephemeral 未每次新生成，按端独立性削弱")
	}
	if bytes.Equal(first[4:36], second[4:36]) {
		t.Fatal("两次封装的信封内 ephPub 字段相同 ⇒ 复用了同一临时密钥对")
	}

	for i, wrapped := range [][]byte{first, second} {
		got, err := UnwrapDEK(wrapped, devPriv)
		if err != nil {
			t.Fatalf("第 %d 份信封 UnwrapDEK: %v", i+1, err)
		}
		if !bytes.Equal(got, dek) {
			t.Errorf("第 %d 份信封解出 %x, 期望 %x", i+1, got, dek)
		}
	}
}

// TestWrapRejectsInvalidPublicKeys 全零(低阶点)公钥必须被拒绝,不得产出可解密材料。
func TestWrapRejectsInvalidPublicKeys(t *testing.T) {
	dek, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WrapDEK(dek, make([]byte, 32)); err == nil {
		t.Fatal("全零 devPub 应返回 error")
	}
}
