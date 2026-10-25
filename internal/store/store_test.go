package store

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
)

// openTestStore 在 t.TempDir() 内建库（文件名取 material.ServerDBFile 常量，
// 与静息材料清单一致），并设 JINTENG_DIR 隔离，绝不触碰真实 ~/.jinteng/。
func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	path := filepath.Join(dir, material.ServerDBFile)
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st, path
}

func mustNewDevice(t *testing.T) (pub, priv []byte) {
	t.Helper()
	pub, priv, err := crypto.NewDevice()
	if err != nil {
		t.Fatalf("crypto.NewDevice: %v", err)
	}
	return pub, priv
}

func mustWrap(t *testing.T, dek, pub []byte) []byte {
	t.Helper()
	w, err := crypto.WrapDEK(dek, pub)
	if err != nil {
		t.Fatalf("crypto.WrapDEK: %v", err)
	}
	return w
}

// TestRevokeDoesNotRewrapOthers 落实不重包语义：撤销只置状态位，
// 其余设备（含被撤销端自身）的 wrap 值必须逐字节不变。
func TestRevokeDoesNotRewrapOthers(t *testing.T) {
	st, _ := openTestStore(t)

	pubA, _ := mustNewDevice(t)
	pubB, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pubA, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-a): %v", err)
	}
	if err := st.AddDevice("dev-b", pubB, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-b): %v", err)
	}

	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	ciphertext, err := crypto.SealValue(dek, []byte("synthetic-value"))
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	wraps := map[string][]byte{
		"dev-a": mustWrap(t, dek, pubA),
		"dev-b": mustWrap(t, dek, pubB),
	}
	if err := st.PutSecret(idxOf(t, "db/url"), nameCipherOf(t, "db/url"), ciphertext, wraps); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	_, before, err := st.GetSecret(idxOf(t, "db/url"))
	if err != nil {
		t.Fatalf("GetSecret（撤销前）: %v", err)
	}
	if err := st.RevokeDevice("dev-a"); err != nil {
		t.Fatalf("RevokeDevice(dev-a): %v", err)
	}
	afterCT, after, err := st.GetSecret(idxOf(t, "db/url"))
	if err != nil {
		t.Fatalf("GetSecret（撤销后）: %v", err)
	}

	if len(after) != len(before) {
		t.Fatalf("撤销后 wrap 条目数 = %d，期望不变（%d）", len(after), len(before))
	}
	for id, w := range before {
		if !bytes.Equal(w, after[id]) {
			t.Errorf("设备 %s 的 wrap 在撤销后被改写（字节必须一致）", id)
		}
	}
	if !bytes.Equal(afterCT, ciphertext) {
		t.Error("密文在撤销后被改写")
	}

	dA, err := st.Device("dev-a")
	if err != nil {
		t.Fatalf("Device(dev-a): %v", err)
	}
	if !dA.Revoked || dA.ID != "dev-a" || !bytes.Equal(dA.DhPub, pubA) {
		t.Errorf("Device(dev-a) = %+v，期望 Revoked=true 且 ID/Pub 不变", dA)
	}
	dB, err := st.Device("dev-b")
	if err != nil {
		t.Fatalf("Device(dev-b): %v", err)
	}
	if dB.Revoked {
		t.Error("dev-b 不应被撤销")
	}
}

// TestRotateAfterRevokeOldWrapUnusable 用真材料走完整轮换路径：
// 旧 DEK 加密旧值并包给设备 A → 撤销 A → 轮换（新 DEK 重新 Seal 并重新 WrapDEK）
// → 断言 A 的旧 wrap 副本解出的密钥打不开新密文（不可桩化为布尔标记）。
func TestRotateAfterRevokeOldWrapUnusable(t *testing.T) {
	st, _ := openTestStore(t)

	pubA, privA := mustNewDevice(t)
	pubB, privB := mustNewDevice(t)
	for id, pub := range map[string][]byte{"dev-a": pubA, "dev-b": pubB} {
		if err := st.AddDevice(id, pub, sigPubOf(t)); err != nil {
			t.Fatalf("AddDevice(%s): %v", id, err)
		}
	}

	plain := []byte("synthetic-credential")
	dek1, err := crypto.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK(dek1): %v", err)
	}
	value1, err := crypto.SealValue(dek1, plain)
	if err != nil {
		t.Fatalf("SealValue(value1): %v", err)
	}
	wrapA1 := mustWrap(t, dek1, pubA) // A 此后一直持有的旧 wrap 副本
	wrapB1 := mustWrap(t, dek1, pubB)
	if err := st.PutSecret(idxOf(t, "api/token"), nameCipherOf(t, "api/token"), value1, map[string][]byte{"dev-a": wrapA1, "dev-b": wrapB1}); err != nil {
		t.Fatalf("PutSecret（初始）: %v", err)
	}

	if err := st.RevokeDevice("dev-a"); err != nil {
		t.Fatalf("RevokeDevice(dev-a): %v", err)
	}

	// 轮换：新 DEK 重新 Seal，按端 wrap 整体替换（只留给未撤销的 B）
	dek2, err := crypto.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK(dek2): %v", err)
	}
	value2, err := crypto.SealValue(dek2, plain)
	if err != nil {
		t.Fatalf("SealValue(value2): %v", err)
	}
	wrapB2 := mustWrap(t, dek2, pubB)
	if err := st.PutSecret(idxOf(t, "api/token"), nameCipherOf(t, "api/token"), value2, map[string][]byte{"dev-b": wrapB2}); err != nil {
		t.Fatalf("PutSecret（轮换）: %v", err)
	}

	_, wrapsNow, err := st.GetSecret(idxOf(t, "api/token"))
	if err != nil {
		t.Fatalf("GetSecret（轮换后）: %v", err)
	}
	if _, ok := wrapsNow["dev-a"]; ok {
		t.Error("轮换后库内仍留被撤销端 dev-a 的 wrap，覆盖语义应整体替换")
	}

	// A 的旧 wrap 副本仍能解出「某个」密钥（那是旧 DEK），但旧密钥打不开新密文
	oldKey, err := crypto.UnwrapDEK(wrapA1, privA)
	if err != nil {
		t.Fatalf("A 解自己的旧 wrap 失败: %v", err)
	}
	if bytes.Equal(oldKey, dek2) {
		t.Fatal("A 的旧 wrap 解出了新 DEK——按端封装失效")
	}
	if _, err := crypto.OpenValue(oldKey, value2); err == nil {
		t.Fatal("被撤销端凭旧 wrap 副本解出了轮换后的新密文")
	}

	// 对照组：未撤销的 B 走通新链路（证明拒绝不是普遍性损坏）
	newKey, err := crypto.UnwrapDEK(wrapB2, privB)
	if err != nil {
		t.Fatalf("B 解新 wrap 失败: %v", err)
	}
	if !bytes.Equal(newKey, dek2) {
		t.Fatal("B 解出的密钥不是新 DEK")
	}
	got, err := crypto.OpenValue(newKey, value2)
	if err != nil {
		t.Fatalf("B 用新 DEK 开新密文失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("B 解出 %q，期望 %q", got, plain)
	}
}

// TestDeviceUniqueness：重复 id 拒绝；不存在 id 的读取与撤销返回 error。
func TestDeviceUniqueness(t *testing.T) {
	st, _ := openTestStore(t)

	pub, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pub, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice 首次应成功: %v", err)
	}
	otherPub, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", otherPub, sigPubOf(t)); err == nil {
		t.Error("AddDevice 重复 id 应返回 error")
	}
	if err := st.AddDevice("", pub, sigPubOf(t)); err == nil {
		t.Error("AddDevice 空 id 应返回 error")
	}
	if err := st.AddDevice("dev-bad", bytes.Repeat([]byte{0xAB}, 31), sigPubOf(t)); err == nil {
		t.Error("AddDevice 非法公钥长度应返回 error")
	}

	if _, err := st.Device("ghost"); err == nil {
		t.Error("Device 不存在 id 应返回 error")
	}
	if err := st.RevokeDevice("ghost"); err == nil {
		t.Error("RevokeDevice 不存在 id 应返回 error")
	}

	// 冲突不得破坏已有记录
	d, err := st.Device("dev-a")
	if err != nil {
		t.Fatalf("Device(dev-a): %v", err)
	}
	if !bytes.Equal(d.DhPub, pub) || d.Revoked {
		t.Errorf("重复注册后 dev-a 记录被改动: %+v", d)
	}
}

// TestPutSecretSemantics：非法输入拒绝；同名覆盖＝新密文替换旧密文、
// 该名全部按端 wrap 整体替换；数据跨重开持久（文件名与 material 清单一致）。
func TestPutSecretSemantics(t *testing.T) {
	st, path := openTestStore(t)

	dek, _ := crypto.NewDEK()
	ct, err := crypto.SealValue(dek, []byte("v1"))
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	if err := st.PutSecret("", nameCipherOf(t, "n"), ct, nil); err == nil {
		t.Error("PutSecret 空 name 应返回 error")
	}
	if err := st.PutSecret(idxOf(t, "n"), nil, nil, nil); err == nil {
		t.Error("PutSecret 空密文应返回 error")
	}
	if err := st.PutSecret(idxOf(t, "n"), nameCipherOf(t, "n"), []byte{}, nil); err == nil {
		t.Error("PutSecret 零长密文应返回 error")
	}
	if err := st.PutSecret("n\x00x", nameCipherOf(t, "n"), ct, nil); err == nil {
		t.Error("PutSecret 含 NUL 的 name 应返回 error（复合键分隔符）")
	}
	pubA, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pubA, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := st.PutSecret(idxOf(t, "n"), nameCipherOf(t, "n"), ct, map[string][]byte{"": mustWrap(t, dek, pubA)}); err == nil {
		t.Error("PutSecret 空设备 id 的 wrap 应返回 error")
	}

	if err := st.PutSecret(idxOf(t, "db/url"), nameCipherOf(t, "db/url"), ct, map[string][]byte{"dev-a": mustWrap(t, dek, pubA)}); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if _, _, err := st.GetSecret(idxOf(t, "ghost/name")); err == nil {
		t.Error("GetSecret 不存在 name 应返回 error")
	}

	// 同名覆盖：旧 wrap（dev-a）整体替换为新集合（dev-b）
	pubB, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-b", pubB, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-b): %v", err)
	}
	ct2, err := crypto.SealValue(dek, []byte("v2"))
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	wrapB := mustWrap(t, dek, pubB)
	if err := st.PutSecret(idxOf(t, "db/url"), nameCipherOf(t, "db/url"), ct2, map[string][]byte{"dev-b": wrapB}); err != nil {
		t.Fatalf("PutSecret（覆盖）: %v", err)
	}
	gotCT, gotWraps, err := st.GetSecret(idxOf(t, "db/url"))
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !bytes.Equal(gotCT, ct2) {
		t.Error("覆盖后密文不是新值")
	}
	if _, ok := gotWraps["dev-a"]; ok {
		t.Error("覆盖后仍残留旧设备 dev-a 的 wrap")
	}
	if !bytes.Equal(gotWraps["dev-b"], wrapB) {
		t.Error("覆盖后 dev-b 的 wrap 与新写入值不一致")
	}

	// 重开持久化
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("重开 Open: %v", err)
	}
	defer st2.Close()
	gotCT, gotWraps, err = st2.GetSecret(idxOf(t, "db/url"))
	if err != nil {
		t.Fatalf("重开后 GetSecret: %v", err)
	}
	if !bytes.Equal(gotCT, ct2) || !bytes.Equal(gotWraps["dev-b"], wrapB) {
		t.Error("重开库后数据与关闭前不一致")
	}
	if d, err := st2.Device("dev-b"); err != nil || !bytes.Equal(d.DhPub, pubB) {
		t.Errorf("重开后设备记录异常: %+v, %v", d, err)
	}
}

// TestNonceDedupePersistsAcrossReopen 落实 spec「重放判定在服务端重启之后仍然
// 成立」：nonce 落 bbolt 而不是进程内存，Close 后重开必须仍判定为重放。
func TestNonceDedupePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	path := filepath.Join(dir, material.ServerDBFile)

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.NoteNonce("dev-a", "nonce-1"); err != nil {
		t.Fatalf("NoteNonce: %v", err)
	}
	if seen, err := st.SeenNonce("dev-a", "nonce-1"); err != nil || !seen {
		t.Fatalf("写入后 SeenNonce=(%v,%v), 期望 (true,nil)", seen, err)
	}
	if seen, err := st.SeenNonce("dev-a", "nonce-2"); err != nil || seen {
		t.Fatalf("未见过的 nonce SeenNonce=(%v,%v), 期望 (false,nil)", seen, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if seen, err := st2.SeenNonce("dev-a", "nonce-1"); err != nil || !seen {
		t.Fatalf("重开后 SeenNonce=(%v,%v), 期望重放判定仍成立 (true,nil)", seen, err)
	}
}

// TestNonceBoundKeeps512PerDevice 每端保留最近 512 条（有界，不无限增长）;
// 一端的溢出不得抹掉另一端的记录。
func TestNonceBoundKeeps512PerDevice(t *testing.T) {
	st, _ := openTestStore(t)
	if err := st.NoteNonce("dev-b", "nonce-0000"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		if err := st.NoteNonce("dev-a", fmt.Sprintf("nonce-%04d", i)); err != nil {
			t.Fatalf("NoteNonce %d: %v", i, err)
		}
	}
	if seen, err := st.SeenNonce("dev-a", "nonce-0000"); err != nil || seen {
		t.Errorf("最早的 nonce 应已被挤出（seen=%v err=%v）", seen, err)
	}
	if seen, err := st.SeenNonce("dev-a", "nonce-0599"); err != nil || !seen {
		t.Errorf("最新的 nonce 应仍在表内（seen=%v err=%v）", seen, err)
	}
	if seen, err := st.SeenNonce("dev-b", "nonce-0000"); err != nil || !seen {
		t.Errorf("dev-a 溢出不得影响 dev-b 的记录（seen=%v err=%v）", seen, err)
	}
}

// ---- 命名密钥化与双公钥登记----

var testLibKey = bytes.Repeat([]byte{0x5a}, 32) // 合成库密钥,仅测试内使用

func idxOf(t *testing.T, name string) string {
	t.Helper()
	i, err := crypto.NameIndex(testLibKey, []byte(name))
	if err != nil {
		t.Fatalf("NameIndex(%q): %v", name, err)
	}
	return i
}

func nameCipherOf(t *testing.T, name string) []byte {
	t.Helper()
	c, err := crypto.SealName(testLibKey, []byte(name))
	if err != nil {
		t.Fatalf("SealName(%q): %v", name, err)
	}
	return c
}

func pairingRecord(t *testing.T) Pairing {
	t.Helper()
	return Pairing{ExpiresAt: time.Now().Add(10 * time.Minute).Unix(), Record: []byte("opaque-record")}
}

func sigPubOf(t *testing.T) []byte {
	t.Helper()
	pub, _, err := crypto.NewSignKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestDeviceRecordRejectsLegacy33BLength 旧长度记录（revoked|单公钥＝33 B）必须
// 被显式拒绝，不做兼容读（spec「旧格式…不得被静默接受」）。
func TestDeviceRecordRejectsLegacy33BLength(t *testing.T) {
	st, _ := openTestStore(t)
	legacy := append([]byte{0}, bytes.Repeat([]byte{0xAB}, 32)...)
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).Put([]byte("dev-old"), legacy)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Device("dev-old"); err == nil {
		t.Error("Device 静默接受了 33 B 旧记录")
	}
	if _, err := st.ListDevices(); err == nil {
		t.Error("ListDevices 静默接受了 33 B 旧记录")
	}
}

// TestAddDeviceStoresBothPubkeys 登记必须同时收下加密公钥与签名公钥，
// 且两者都能原样读回；任一长度非法都拒绝。
func TestAddDeviceStoresBothPubkeys(t *testing.T) {
	st, _ := openTestStore(t)
	dhPub, _ := mustNewDevice(t)
	sigPub := sigPubOf(t)
	if err := st.AddDevice("dev-a", dhPub, sigPub); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	d, err := st.Device("dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.DhPub, dhPub) || !bytes.Equal(d.SigPub, sigPub) {
		t.Errorf("双公钥读回不符: %+v", d)
	}
	if err := st.AddDevice("dev-b", dhPub, bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Error("sig_pub 长度非法应返回 error")
	}
	all, err := st.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != "dev-a" {
		t.Errorf("ListDevices = %+v, 期望只含 dev-a", all)
	}
}

// TestSecretStoredUnderBlindIndexKey 落实 Review Focus 5：库内查找键是盲索引、
// 真名只以密文存在；明文名不得作为任何桶的键出现。
func TestSecretStoredUnderBlindIndexKey(t *testing.T) {
	st, _ := openTestStore(t)
	const name = "SYNTH_DB_URL"
	idx := idxOf(t, name)
	dek, _ := crypto.NewDEK()
	ct, err := crypto.SealValue(dek, []byte("synthetic-value"))
	if err != nil {
		t.Fatal(err)
	}
	pubA, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pubA, sigPubOf(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSecret(idx, nameCipherOf(t, name), ct, map[string][]byte{"dev-a": mustWrap(t, dek, pubA)}); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	err = st.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketSecrets).Get([]byte(name)); v != nil {
			t.Error("secrets 桶仍以明文名为键")
		}
		if v := tx.Bucket(bucketSecrets).Get([]byte(idx)); v == nil {
			t.Error("secrets 桶缺盲索引键")
		}
		nc := tx.Bucket(bucketNames).Get([]byte(idx))
		if nc == nil {
			t.Error("names 桶缺该索引的名字密文")
		}
		if bytes.Contains(nc, []byte(name)) {
			t.Error("名字密文里出现了明文名")
		}
		wk := append(append([]byte(nil), []byte(idx)...), keySep)
		wk = append(wk, "dev-a"...)
		if v := tx.Bucket(bucketWraps).Get(wk); v == nil {
			t.Errorf("wraps 桶键应为盲索引\\x00deviceId，实际缺失（键 %q）", wk)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

// TestPairingRecordRoundTripAndConsume 配对码记录：按索引写入不透明密文、
// 读回 TTL、用后即失效（spec「配对码用过一次即失效」的库侧地基）。
func TestPairingRecordRoundTripAndConsume(t *testing.T) {
	st, _ := openTestStore(t)
	idx := idxOf(t, "synthetic-pair-code")
	rec := []byte("opaque-encrypted-record")
	if err := st.PutPairing(idx, Pairing{ExpiresAt: 2_000_000_000, Record: rec}); err != nil {
		t.Fatalf("PutPairing: %v", err)
	}
	p, err := st.Pairing(idx)
	if err != nil {
		t.Fatal(err)
	}
	if p.ExpiresAt != 2_000_000_000 || p.Consumed || !bytes.Equal(p.Record, rec) {
		t.Errorf("Pairing 读回 %+v", p)
	}
	if err := st.MarkPairingConsumed(idx); err != nil {
		t.Fatal(err)
	}
	p2, err := st.Pairing(idx)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Consumed {
		t.Error("MarkPairingConsumed 未置消费位")
	}
	if _, err := st.Pairing(idxOf(t, "never-issued")); err == nil {
		t.Error("未签发的配对码索引应返回 ErrNotFound")
	}
}

// TestClaimNonceIsAtomic 钉住「同一随机值被重放 ⇒ 拒绝」在并发下仍成立：
// 判定与写入必须在同一个 Update 事务里（check-then-act 会留下 120 s 窗口内的
// 双发通过）。同时钉住自驱逐：刚插入的那条不得被自己挤掉。
func TestClaimNonceIsAtomic(t *testing.T) {
	st, _ := openTestStore(t)
	seen, err := st.ClaimNonce("dev-a", "nonce-1")
	if err != nil || seen {
		t.Fatalf("首次 ClaimNonce=(%v,%v)，期望 (false,nil)", seen, err)
	}
	seen, err = st.ClaimNonce("dev-a", "nonce-1")
	if err != nil || !seen {
		t.Fatalf("第二次 ClaimNonce=(%v,%v)，期望 (true,nil)", seen, err)
	}
	for i := 0; i < 601; i++ {
		seen, err := st.ClaimNonce("dev-b", fmt.Sprintf("nonce-%04d", i))
		if err != nil {
			t.Fatal(err)
		}
		if seen {
			t.Fatalf("nonce-%04d 被判为重放（自驱逐或计数错误）", i)
		}
	}
	if s, _ := st.SeenNonce("dev-b", "nonce-0600"); !s {
		t.Error("刚写入的 nonce 被自己的有界驱逐删掉了（该请求的窗口防护当场失效）")
	}
}

// ── Verify 退回轮（2026-10-16）：写事务内的不变量 ──

// PutSecret 的 wraps↔devices 校验必须发生在同一条写事务里：判定与落库分两步时，
// 「取完名录与落库之间刚被撤销」的端仍能拿到新 DEK 副本，注释声称的不变量不成立。
func TestPutSecretRejectsWrapForRevokedDeviceInTx(t *testing.T) {
	st, _ := openTestStore(t)
	pubA, _ := mustNewDevice(t)
	pubB, _ := mustNewDevice(t)
	sigA := sigPubOf(t)
	if err := st.AddDevice("dev-a", pubA, sigA); err != nil {
		t.Fatal(err)
	}
	if err := st.AddDevice("dev-b", pubB, sigA); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice("dev-b"); err != nil {
		t.Fatal(err)
	}
	dek, _ := crypto.NewDEK()
	ct, err := crypto.SealValue(dek, []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	w := mustWrap(t, dek, pubB)
	if err := st.PutSecret(idxOf(t, "n"), nameCipherOf(t, "n"), ct, map[string][]byte{"dev-a": w, "dev-b": w}); err == nil {
		t.Error("wraps 含已撤销端时 store 层应拒绝（不得只靠调用方先查一次）")
	}
	if _, _, err := st.GetSecret(idxOf(t, "n")); err == nil {
		t.Error("被拒的写入不得落库")
	}
}

func TestPutSecretRejectsWrapForUnknownDevice(t *testing.T) {
	st, _ := openTestStore(t)
	pubA, _ := mustNewDevice(t)
	sigA := sigPubOf(t)
	if err := st.AddDevice("dev-a", pubA, sigA); err != nil {
		t.Fatal(err)
	}
	dek, _ := crypto.NewDEK()
	ct, err := crypto.SealValue(dek, []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	w := mustWrap(t, dek, pubA)
	if err := st.PutSecret(idxOf(t, "n"), nameCipherOf(t, "n"), ct, map[string][]byte{"dev-ghost": w}); err == nil {
		t.Error("wraps 含未注册端时 store 层应拒绝")
	}
}

// Enroll 把「配对码判定＋消费」「顶替闸」「落库」收进同一条写事务：
// 码不可用或端冲突时整笔回滚，码不被烧掉。
func TestEnrollConsumesCodeAndRegistersInOneTx(t *testing.T) {
	st, _ := openTestStore(t)
	dhA, _ := mustNewDevice(t)
	sigA := sigPubOf(t)
	if err := st.PutPairing("code-1", pairingRecord(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("code-1", "dev-a", dhA, sigA); err != nil {
		t.Fatalf("有效码登记新端应成功：%v", err)
	}
	if p, err := st.Pairing("code-1"); err != nil || !p.Consumed {
		t.Errorf("登记成功后码应被消费，得 %+v err=%v", p, err)
	}
	// 同一枚码第二次：既不再产生端，也不得改动已有端
	dhB, _ := mustNewDevice(t)
	sigB := sigPubOf(t)
	if err := st.Enroll("code-1", "dev-b", dhB, sigB); err == nil {
		t.Error("已消费的码应被拒")
	}
	if _, err := st.Device("dev-b"); err == nil {
		t.Error("被拒的登记不得产生新端")
	}
}

func TestEnrollKeepsActiveDeviceKeysAndCode(t *testing.T) {
	st, _ := openTestStore(t)
	dhA, _ := mustNewDevice(t)
	sigA := sigPubOf(t)
	dhB, _ := mustNewDevice(t)
	dhC, _ := mustNewDevice(t)
	sigB := sigPubOf(t)
	if err := st.AddDevice("dev-a", dhA, sigA); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPairing("code-2", pairingRecord(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("code-2", "dev-a", dhB, sigB); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("未撤销在册端换签名公钥应 ErrDeviceExists，得 %v", err)
	}
	dev, err := st.Device("dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dev.DhPub, dhA) || !bytes.Equal(dev.SigPub, sigA) {
		t.Error("冲突的登记改动了已有端的公钥")
	}
	if p, err := st.Pairing("code-2"); err != nil || p.Consumed {
		t.Errorf("冲突的登记不得烧掉配对码，得 %+v err=%v", p, err)
	}
	// 同一枚码仍可登记另一台端
	if err := st.Enroll("code-2", "dev-c", dhC, sigB); err != nil {
		t.Errorf("未消费的码应可用于新端：%v", err)
	}
}

func TestEnrollRevokedDeviceAnchorsSigPub(t *testing.T) {
	st, _ := openTestStore(t)
	dhA, _ := mustNewDevice(t)
	sigA := sigPubOf(t)
	dhB, _ := mustNewDevice(t)
	sigB := sigPubOf(t)
	if err := st.AddDevice("dev-a", dhA, sigA); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice("dev-a"); err != nil {
		t.Fatal(err)
	}
	// 撤销态下换签名公钥＝身份顶替，必须拒（spec 场景说的是同一把钥的真端）
	if err := st.PutPairing("code-3", pairingRecord(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("code-3", "dev-a", dhB, sigB); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("撤销态下换签名公钥应 ErrDeviceExists，得 %v", err)
	}
	// 同一把签名公钥＋换加密公钥：允许，并清撤销位（密钥轮换后重新登记）
	if err := st.PutPairing("code-4", pairingRecord(t)); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("code-4", "dev-a", dhB, sigA); err != nil {
		t.Fatalf("同签名公钥重登记应成功：%v", err)
	}
	if d, err := st.Device("dev-a"); err != nil || d.Revoked || !bytes.Equal(d.DhPub, dhB) {
		t.Errorf("重登记后应清撤销位并换新加密公钥，得 %+v err=%v", d, err)
	}
}

func TestEnrollRejectsExpiredCode(t *testing.T) {
	st, _ := openTestStore(t)
	dh, _ := mustNewDevice(t)
	if err := st.PutPairing("code-x", Pairing{ExpiresAt: 1, Record: []byte("r")}); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("code-x", "dev-a", dh, sigPubOf(t)); err == nil {
		t.Error("过期码登记应被拒")
	}
	if _, err := st.Device("dev-a"); err == nil {
		t.Error("过期码不得产生在册端")
	}
}

// TestDeleteSecretSemantics：删除在单条写事务内清空 secrets/names/wraps 三桶；
// 缺失与非法索引不改变数据。
func TestDeleteSecretSemantics(t *testing.T) {
	st, _ := openTestStore(t)

	pubA, _ := mustNewDevice(t)
	pubB, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pubA, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-a): %v", err)
	}
	if err := st.AddDevice("dev-b", pubB, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-b): %v", err)
	}
	dek, _ := crypto.NewDEK()
	ct, err := crypto.SealValue(dek, []byte("v1"))
	if err != nil {
		t.Fatalf("SealValue: %v", err)
	}
	index := idxOf(t, "db/url")
	if err := st.PutSecret(index, nameCipherOf(t, "db/url"), ct, map[string][]byte{
		"dev-a": mustWrap(t, dek, pubA),
		"dev-b": mustWrap(t, dek, pubB),
	}); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	// 非法索引在任何写入前拒绝，既有数据不变。
	for _, bad := range []string{"", "x\x00y"} {
		if err := st.DeleteSecret(bad); err == nil {
			t.Errorf("DeleteSecret(%q) 应返回 error", bad)
		}
	}
	if _, wraps, err := st.GetSecret(index); err != nil || len(wraps) != 2 {
		t.Fatalf("非法删除后既有数据被改动: wraps=%d err=%v", len(wraps), err)
	}

	// 缺失索引返回 ErrNotFound。
	if err := st.DeleteSecret(idxOf(t, "ghost/name")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSecret(缺失) = %v, 期望 ErrNotFound", err)
	}

	if err := st.DeleteSecret(index); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, _, err := st.GetSecret(index); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后 GetSecret = %v, 期望 ErrNotFound", err)
	}
	if err := st.DeleteSecret(index); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复删除 = %v, 期望 ErrNotFound", err)
	}

	// 原始三桶：secrets/names 无该键，wraps 无该前缀。
	if err := st.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketSecrets).Get([]byte(index)); v != nil {
			t.Error("删除后 secrets 桶仍残留密文")
		}
		if v := tx.Bucket(bucketNames).Get([]byte(index)); v != nil {
			t.Error("删除后 names 桶仍残留名字密文")
		}
		prefix := namePrefix(index)
		c := tx.Bucket(bucketWraps).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			t.Errorf("删除后 wraps 桶仍残留键 %q", k)
		}
		return nil
	}); err != nil {
		t.Fatalf("检查桶: %v", err)
	}
}

// TestDeleteThenRePutLeavesNoOldWraps：删除后同名重写只保留新批次 wrap，
// 旧密文与旧 wrap 不残留。
func TestDeleteThenRePutLeavesNoOldWraps(t *testing.T) {
	st, _ := openTestStore(t)

	pubA, _ := mustNewDevice(t)
	pubB, _ := mustNewDevice(t)
	if err := st.AddDevice("dev-a", pubA, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-a): %v", err)
	}
	if err := st.AddDevice("dev-b", pubB, sigPubOf(t)); err != nil {
		t.Fatalf("AddDevice(dev-b): %v", err)
	}
	dek, _ := crypto.NewDEK()
	index := idxOf(t, "api/token")
	ct1, err := crypto.SealValue(dek, []byte("v1"))
	if err != nil {
		t.Fatalf("SealValue(v1): %v", err)
	}
	if err := st.PutSecret(index, nameCipherOf(t, "api/token"), ct1, map[string][]byte{
		"dev-a": mustWrap(t, dek, pubA),
		"dev-b": mustWrap(t, dek, pubB),
	}); err != nil {
		t.Fatalf("PutSecret(v1): %v", err)
	}
	if err := st.DeleteSecret(index); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	ct2, err := crypto.SealValue(dek, []byte("v2"))
	if err != nil {
		t.Fatalf("SealValue(v2): %v", err)
	}
	wrapB2 := mustWrap(t, dek, pubB)
	if err := st.PutSecret(index, nameCipherOf(t, "api/token"), ct2, map[string][]byte{"dev-b": wrapB2}); err != nil {
		t.Fatalf("PutSecret(v2): %v", err)
	}
	gotCT, gotWraps, err := st.GetSecret(index)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !bytes.Equal(gotCT, ct2) {
		t.Error("重写后密文不是新值")
	}
	if len(gotWraps) != 1 || !bytes.Equal(gotWraps["dev-b"], wrapB2) {
		t.Errorf("重写后 wrap 集合异常: %v", gotWraps)
	}
	if _, ok := gotWraps["dev-a"]; ok {
		t.Error("重写后仍残留 dev-a 的旧 wrap")
	}
}
