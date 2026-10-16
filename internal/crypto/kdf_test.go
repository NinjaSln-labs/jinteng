package crypto

import (
	"bytes"
	"testing"
)

// 测试一律使用合成口令与合成值，不使用任何真实凭据。
const syntheticPassphrase = "synthetic-passphrase-not-a-real-credential"

func fingerprint32(seed byte) []byte {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = seed + byte(i)
	}
	return fp
}

func TestDeriveKEKDifferentFingerprint(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, SaltLen)
	k1, err := DeriveKEK(syntheticPassphrase, fingerprint32(1), salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	k2, err := DeriveKEK(syntheticPassphrase, fingerprint32(2), salt)
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("KEK 长度 = %d/%d, want 32", len(k1), len(k2))
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("同口令同 salt、异指纹必须派生出不同 KEK")
	}
}

func TestDeriveKEKDifferentSalt(t *testing.T) {
	fp := fingerprint32(7)
	k1, err := DeriveKEK(syntheticPassphrase, fp, bytes.Repeat([]byte{0x01}, SaltLen))
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	k2, err := DeriveKEK(syntheticPassphrase, fp, bytes.Repeat([]byte{0x02}, SaltLen))
	if err != nil {
		t.Fatalf("DeriveKEK: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("同口令同指纹、异 salt 必须派生出不同 KEK")
	}
}

func TestDeriveKEKRejectsInvalidInputs(t *testing.T) {
	fp := fingerprint32(3)
	if _, err := DeriveKEK(syntheticPassphrase, fp, []byte{0x01, 0x02}); err == nil {
		t.Fatal("salt 非 16 字节必须 error")
	}
	if _, err := DeriveKEK(syntheticPassphrase, nil, bytes.Repeat([]byte{0x01}, SaltLen)); err == nil {
		t.Fatal("空指纹必须 error，不得继续派生")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("DEK 长度 = %d, want 32", len(key))
	}
	plain := []byte("synthetic-credential-value")
	blob, err := SealValue(key, plain)
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	// 布局 magic(4) | nonce(12) | ciphertext(+16 B GCM tag)
	if want := 4 + 12 + len(plain) + 16; len(blob) != want {
		t.Fatalf("blob 长度 = %d, want %d", len(blob), want)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("信封中出现明文，SealValue 未加密")
	}
	got, err := OpenValue(key, blob)
	if err != nil {
		t.Fatalf("OpenValue: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip 不一致: got %q", got)
	}
}

func TestOpenValueWrongKeyFails(t *testing.T) {
	k1, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	k2, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	blob, err := SealValue(k1, []byte("synthetic-credential-value"))
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	if _, err := OpenValue(k2, blob); err == nil {
		t.Fatal("错误密钥必须解密失败")
	}
}

func TestOpenValueRejectsTruncatedBlob(t *testing.T) {
	key, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	plain := []byte("synthetic-credential-value")
	blob, err := SealValue(key, plain)
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	for _, cut := range []int{len(blob) - 1, 4 + 12, 4, 0} {
		if _, err := OpenValue(key, blob[:cut]); err == nil {
			t.Fatalf("截断到 %d 字节的 blob 必须返回 error", cut)
		}
	}
}
