package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// 本文件所有密钥与消息均为合成值。

// TestSignKeyRoundTrip 钉住这条：NewSignKey 产出的 pub 必须由 seed 唯一决定
// （登记时上报 pub、封存时存 seed，两侧必须是同一把钥匙）。
func TestSignKeyRoundTrip(t *testing.T) {
	pub, seed, err := NewSignKey()
	if err != nil {
		t.Fatalf("NewSignKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(seed) != ed25519.SeedSize {
		t.Fatalf("密钥长度 pub=%d seed=%d, 期望各 %d/%d",
			len(pub), len(seed), ed25519.PublicKeySize, ed25519.SeedSize)
	}
	want := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(pub, []byte(want.Public().(ed25519.PublicKey))) {
		t.Error("pub 与 seed 派生的公钥不一致")
	}
	pub2, seed2, err := NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(seed, seed2) || bytes.Equal(pub, pub2) {
		t.Error("两次 NewSignKey 输出了相同密钥")
	}
}

// TestSignVerifySelfConsistent 落实「验签即验证」：用登记时上报的 sig_pub
// 能验通该 key 自己签出的字节；改一个字节即验不通。
func TestSignVerifySelfConsistent(t *testing.T) {
	pub, seed, err := NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("synthetic-canonical:POST\n/v2/enroll\n\naGVsbG8=")
	sig, err := SignWithSeed(seed, msg)
	if err != nil {
		t.Fatalf("SignWithSeed: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("签名长度 = %d, 期望 %d", len(sig), ed25519.SignatureSize)
	}
	if !VerifySig(pub, msg, sig) {
		t.Error("自洽签名验不通")
	}
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if VerifySig(pub, tampered, sig) {
		t.Error("消息被改一字节后仍验通")
	}
	otherPub, _, err := NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	if VerifySig(otherPub, msg, sig) {
		t.Error("别端公钥验通了这条签名")
	}
}
