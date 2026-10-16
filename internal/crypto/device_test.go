package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// 本文件所有口令与密钥材料均为合成值。

// TestNewDeviceShape 断言 NewDevice 产出 32 字节的 X25519 公私钥且逐次不同。
func TestNewDeviceShape(t *testing.T) {
	pub1, priv1, err := NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	if len(pub1) != 32 || len(priv1) != 32 {
		t.Fatalf("密钥长度 pub=%d priv=%d, 期望各 32", len(pub1), len(priv1))
	}
	pub2, priv2, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(priv1, priv2) || bytes.Equal(pub1, pub2) {
		t.Fatal("两次 NewDevice 输出了相同密钥")
	}
}

// TestSealOpenDeviceKeysRoundTrip 断言 JDK2 信封布局 magic(4) | salt(16) |
// nonce(12) | ciphertext,载荷为 dhPriv(32) ‖ sigSeed(32)＝64 B;两次封装的
// salt|nonce 必须不同。
func TestSealOpenDeviceKeysRoundTrip(t *testing.T) {
	const pw = "synthetic-passphrase-R"
	dhPriv := synthKey(0x11)
	sigSeed := synthKey(0x22)
	fp := synthFingerprint(0x33)

	blob1, err := SealDeviceKeys(dhPriv, sigSeed, pw, fp)
	if err != nil {
		t.Fatalf("SealDeviceKeys: %v", err)
	}
	const overhead = 4 + SaltLen + 12 + 16
	if len(blob1) != overhead+64 {
		t.Fatalf("信封长度 = %d, 期望 %d", len(blob1), overhead+64)
	}
	if !bytes.Equal(blob1[:4], []byte{'J', 'D', 'K', '2'}) {
		t.Errorf("device magic = %q, 期望 %q", blob1[:4], "JDK2")
	}

	blob2, err := SealDeviceKeys(dhPriv, sigSeed, pw, fp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(blob1[4:4+SaltLen+12], blob2[4:4+SaltLen+12]) {
		t.Error("两次封装的 salt|nonce 完全相同,随机性缺失")
	}
}

// TestOpenDeviceKeysReturnsBothSecrets 一次解锁必须同时取回两把私钥，
// 逐字节等于封入值（签名与解密共享同一失效条件）。
func TestOpenDeviceKeysReturnsBothSecrets(t *testing.T) {
	const pw = "synthetic-pw-both"
	dhPriv := synthKey(0x41)
	sigSeed := synthKey(0x42)
	fp := synthFingerprint(0x43)

	blob, err := SealDeviceKeys(dhPriv, sigSeed, pw, fp)
	if err != nil {
		t.Fatal(err)
	}
	gotDh, gotSeed, err := OpenDeviceKeys(blob, pw, fp)
	if err != nil {
		t.Fatalf("OpenDeviceKeys: %v", err)
	}
	if !bytes.Equal(gotDh, dhPriv) {
		t.Error("解出的 X25519 私钥与封入值不一致")
	}
	if !bytes.Equal(gotSeed, sigSeed) {
		t.Error("解出的 Ed25519 seed 与封入值不一致")
	}
}

// TestOpenDeviceKeysRejectsJDK1Magic 落实 Review Focus 4／spec「旧格式封存的
// 设备私钥文件不得被静默接受」：只把 magic 改成 JDK1 也必须以格式不匹配拒绝，
// 不得降级为「能解密但不能签名」的半可用状态。
func TestOpenDeviceKeysRejectsJDK1Magic(t *testing.T) {
	const pw = "synthetic-pw-magic"
	fp := synthFingerprint(0x51)
	blob, err := SealDeviceKeys(synthKey(0x52), synthKey(0x53), pw, fp)
	if err != nil {
		t.Fatal(err)
	}
	legacy := append([]byte{'J', 'D', 'K', '1'}, blob[4:]...)
	dh, seed, err := OpenDeviceKeys(legacy, pw, fp)
	if err == nil {
		t.Fatalf("JDK1 信封被接受（dh=%d seed=%d 字节）", len(dh), len(seed))
	}
	if dh != nil || seed != nil {
		t.Error("拒绝时不得返回任何明文")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error 应点明格式不匹配，得 %v", err)
	}
}

// TestSealDeviceKeysRejectsWrongInputLength 任一入参≠32 B 都必须在派生 KEK
// 之前拒绝（半把钥匙封进信封等于给自己埋一个解不开的端）。
func TestSealDeviceKeysRejectsWrongInputLength(t *testing.T) {
	fp := synthFingerprint(0x61)
	const pw = "synthetic-pw-len"
	if _, err := SealDeviceKeys(synthKey(0x62), []byte("short"), pw, fp); err == nil {
		t.Fatal("sigSeed 长度非法应返回 error")
	}
	if _, err := SealDeviceKeys(make([]byte, 33), synthKey(0x63), pw, fp); err == nil {
		t.Fatal("dhPriv 长度非法应返回 error")
	}
}

// TestOpenDeviceKeysWrongFingerprintFails 同一信封、同口令、异指纹 ⇒ error,
// 且不返回任何明文（机器绑定这条面）。
func TestOpenDeviceKeysWrongFingerprintFails(t *testing.T) {
	const pw = "synthetic-pw-fp"
	blob, err := SealDeviceKeys(synthKey(0x71), synthKey(0x72), pw, synthFingerprint(0x73))
	if err != nil {
		t.Fatal(err)
	}
	dh, seed, err := OpenDeviceKeys(blob, pw, synthFingerprint(0x74))
	if err == nil {
		t.Fatalf("异指纹解开了信封（dh=%d seed=%d 字节）", len(dh), len(seed))
	}
	if dh != nil || seed != nil {
		t.Error("失败时不得同时返回明文")
	}
}

// TestOpenDeviceKeysWrongPassphraseFails 错误口令必须返回 error,且 error 文本
// 不得携带口令本身。
func TestOpenDeviceKeysWrongPassphraseFails(t *testing.T) {
	fp := synthFingerprint(0x44)
	blob, err := SealDeviceKeys(synthKey(0x45), synthKey(0x46), "synthetic-pw-correct", fp)
	if err != nil {
		t.Fatal(err)
	}
	const wrong = "synthetic-pw-wrong"
	dh, seed, err := OpenDeviceKeys(blob, wrong, fp)
	if err == nil {
		t.Fatalf("错误口令解开了设备密钥（dh=%d seed=%d 字节）", len(dh), len(seed))
	}
	if dh != nil || seed != nil {
		t.Error("失败时不得同时返回明文")
	}
	if strings.Contains(err.Error(), wrong) {
		t.Errorf("error 文本携带了口令: %v", err)
	}
}

// TestOpenDeviceKeysTruncatedFails 截断与坏 magic 的 blob 必须在派生 KEK 之前
// 即报错（低成本路径,不触真 KDF）。
func TestOpenDeviceKeysTruncatedFails(t *testing.T) {
	fp := synthFingerprint(0x55)
	blob, err := SealDeviceKeys(synthKey(0x56), synthKey(0x57), "synthetic-pw-T", fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenDeviceKeys(blob[:len(blob)-1], "synthetic-pw-T", fp); err == nil {
		t.Fatal("截断 blob 应返回 error")
	}
	bad := append([]byte(nil), blob...)
	bad[0] = 'X'
	if _, _, err := OpenDeviceKeys(bad, "synthetic-pw-T", fp); err == nil {
		t.Fatal("坏 magic 应返回 error")
	}
}

func synthKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}
