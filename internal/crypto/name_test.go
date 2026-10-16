package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// 本文件所有密钥与名字均为合成值。

func synthLib(t *testing.T) []byte {
	t.Helper()
	k, err := NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestNameIndexDeterministic 钉住这条①：同一 library.key 下同名必得同一索引
// （查找键），异 key 必不同（无 key 者列不出名）。
func TestNameIndexDeterministic(t *testing.T) {
	k1, k2 := synthLib(t), synthLib(t)
	a, err := NameIndex(k1, []byte("SYNTH_NAME"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NameIndex(k1, []byte("SYNTH_NAME"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("同名同 key 索引不稳定: %s vs %s", a, b)
	}
	raw, derr := hex.DecodeString(a)
	if len(a) != 64 || derr != nil || len(raw) != sha256.Size {
		t.Errorf("索引应为 64 位十六进制 HMAC-SHA256, got %q (decode err=%v)", a, derr)
	}
	c, err := NameIndex(k2, []byte("SYNTH_NAME"))
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("异 key 得到同一索引（等于没密钥化）")
	}
	if strings.Contains(a, "SYNTH_NAME") {
		t.Error("索引里出现了明文名")
	}
	d, err := NameIndex(k1, []byte("SYNTH_NAMX"))
	if err != nil {
		t.Fatal(err)
	}
	if d == a {
		t.Error("异名得到同一索引")
	}
}

// TestSealOpenNameRoundTrip 钉住这条②：真名以密文存储且能用同一 key 取回;
// 密文里不得出现明名字节（「只拿到库文件列不出名」这条）。
func TestSealOpenNameRoundTrip(t *testing.T) {
	k := synthLib(t)
	name := []byte("SYNTH_NAME_ROUNDTRIP")
	blob, err := SealName(k, name)
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	if bytes.Contains(blob, name) {
		t.Error("名字密文里出现了明文名片段")
	}
	back, err := OpenName(k, blob)
	if err != nil {
		t.Fatalf("OpenName: %v", err)
	}
	if !bytes.Equal(back, name) {
		t.Errorf("取回的名 %q, 期望 %q", back, name)
	}
}

// TestOpenNameWrongKeyFails 用别的 key 必须解不开，且不返回任何明文。
func TestOpenNameWrongKeyFails(t *testing.T) {
	blob, err := SealName(synthLib(t), []byte("SYNTH_NAME"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenName(synthLib(t), blob)
	if err == nil {
		t.Fatalf("异 key 解开了名字密文: %q", got)
	}
	if got != nil {
		t.Error("失败时不得返回明文")
	}
}

// TestSubKeyDomainSeparation 一钥两用的域分隔必须成立：同一 library.key
// 派生出的名字密钥与配对密钥不得相同（否则命名加密被配对通道稀释）。
func TestSubKeyDomainSeparation(t *testing.T) {
	k := synthLib(t)
	nameKey, err := SubKey(k, "jinteng-name-enc-v1")
	if err != nil {
		t.Fatal(err)
	}
	pairKey, err := SubKey(k, "jinteng-pair-v1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(nameKey, pairKey) {
		t.Error("两个用途派生出同一把子密钥")
	}
	if len(nameKey) != KeyLen || len(pairKey) != KeyLen {
		t.Errorf("子密钥长度 %d/%d, 期望各 %d", len(nameKey), len(pairKey), KeyLen)
	}
	if _, err := SubKey(make([]byte, 16), "jinteng-name-enc-v1"); err == nil {
		t.Error("library.key 长度非法应返回 error")
	}
}
