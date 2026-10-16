package material

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

// 本文件所有口令与密钥材料均为合成值,产物只落在 t.TempDir()。

func synthFP() []byte {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = 0x77 ^ byte(i)
	}
	return fp
}

// TestSaveRejectsWorldReadableMode 落实 Review Focus 1：传入比 0600 更宽松的
// 权限必须报错,而不是静默改权限。
func TestSaveRejectsWorldReadableMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)

	content := []byte("synthetic-sealed-envelope-bytes")
	for _, mode := range []os.FileMode{0644, 0666, 0640, 0755} {
		if err := Save(content, mode); err == nil {
			t.Fatalf("Save(…, %o) 应返回 error 而不是接受过宽权限", mode)
		}
	}
	if err := Save(content, 0600); err != nil {
		t.Fatalf("Save(…, 0600): %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, DeviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("私钥文件权限 = %o, 期望 0600", st.Mode().Perm())
	}
}

// TestLoadKeysWithWrongPassphraseFails 走真 KEK 解密：错误口令必须 error 且无明文;
// 正确口令必须同时取回两把私钥。
func TestLoadKeysWithWrongPassphraseFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)

	fp := synthFP()
	dhPriv, err := crypto.NewDEK() // 合成 32 字节私钥材料
	if err != nil {
		t.Fatal(err)
	}
	sigSeed, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealDeviceKeys(dhPriv, sigSeed, "synthetic-pw-right", fp)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(blob, 0600); err != nil {
		t.Fatal(err)
	}

	if gotDh, gotSeed, err := LoadKeys("synthetic-pw-wrong", fp); err == nil || gotDh != nil || gotSeed != nil {
		t.Fatalf("错误口令 LoadKeys 应失败且无明文, dh=%d seed=%d err=%v", len(gotDh), len(gotSeed), err)
	}
	backDh, backSeed, err := LoadKeys("synthetic-pw-right", fp)
	if err != nil {
		t.Fatalf("正确口令 LoadKeys: %v", err)
	}
	if !bytes.Equal(backDh, dhPriv) {
		t.Error("LoadKeys 取回的 X25519 私钥与封装前不一致")
	}
	if !bytes.Equal(backSeed, sigSeed) {
		t.Error("LoadKeys 取回的 Ed25519 seed 与封装前不一致")
	}
}

// TestInventoryCoversAllRestingMaterials 是静息材料清单的口径测试
// 枚举器的输入契约：必含设备私钥文件／配置／事件日志／服务端库文件,
// 且不包含任何明文值文件（哪怕该文件真实存在于目录中）。
func TestInventoryCoversAllRestingMaterials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	// 在材料目录里放一个明文值文件作为哨兵,清单不得收录它
	if err := os.WriteFile(filepath.Join(dir, "leaked-values.plain"), []byte("PLAIN"), 0600); err != nil {
		t.Fatal(err)
	}

	inv, err := Inventory()
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	set := map[string]bool{}
	for _, p := range inv {
		if filepath.IsAbs(p) || p == "" {
			t.Errorf("清单项 %q 应为非空相对路径", p)
		}
		set[p] = true
	}
	for _, want := range []string{DeviceKeyFile, ConfigFile, EventsFile, ServerDBFile, ServerCertFile, ServerKeyFile} {
		if !set[want] {
			t.Errorf("清单缺少静息材料 %q: %v", want, inv)
		}
	}
	for p := range set {
		if filepath.Base(p) == "leaked-values.plain" {
			t.Errorf("清单不得包含明文值文件: %q", p)
		}
	}
}

// TestDirHonoursEnvOverride 断言 JINTENG_DIR 覆盖与默认目录形状。
func TestDirHonoursEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	if got, err := Dir(); err != nil || got != dir {
		t.Fatalf("Dir() = %q, %v; 期望 %q", got, err, dir)
	}
	t.Setenv("JINTENG_DIR", "")
	got, err := Dir()
	if err != nil {
		t.Fatalf("无覆盖时 Dir(): %v", err)
	}
	if filepath.Base(got) != ".jinteng" {
		t.Errorf("默认目录 = %q, 期望以 .jinteng 结尾", got)
	}
}

// TestSaveCreatesDirAndRejectsMissingDir 验证目录不存在时 Save 自建 0700。
func TestSaveCreatesDirAndRejectsMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "jinteng")
	t.Setenv("JINTENG_DIR", dir)
	if err := Save([]byte("synthetic"), 0600); err != nil {
		t.Fatalf("Save 应自建缺失目录: %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0077 != 0 {
		t.Errorf("材料目录权限 = %o, 不得对组/其他开放", st.Mode().Perm())
	}
}

// TestLibraryKeyGeneratedOnceAt0600 钉住这条：library.key 首次使用即生成并落盘，
// 之后复用同一把；权限位必须 ≤0600（它属服务端静息材料）。
func TestLibraryKeyGeneratedOnceAt0600(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)

	k1, err := LibraryKey()
	if err != nil {
		t.Fatalf("LibraryKey 首次: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("library.key 长度 = %d, 期望 32", len(k1))
	}
	k2, err := LibraryKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Error("两次调用生成了不同的库密钥（复用失效）")
	}
	st, err := os.Stat(dir + string(os.PathSeparator) + LibraryKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&^0600 != 0 {
		t.Errorf("library.key 权限 = %o, 期望 ≤0600", st.Mode().Perm())
	}
}

// TestInventoryIncludesLibraryKey 把声明基线钉成七件——judge2 的整树差集
// 依赖它，漏一件就会被判成清单外材料而直接 fail（design Risks 点名的一条）。
func TestInventoryIncludesLibraryKey(t *testing.T) {
	inv, err := Inventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 7 {
		t.Errorf("清单应为七件, 得 %d 件: %v", len(inv), inv)
	}
	var found bool
	for _, f := range inv {
		if f == LibraryKeyFile {
			found = true
		}
	}
	if !found {
		t.Errorf("清单缺 %q: %v", LibraryKeyFile, inv)
	}
}

// TestLibraryKeyDoesNotOverwriteUnreadableFile 钉住一次真实风险：库密钥文件存在但
// 读不出来（权限／IO 错误）时，绝不能「另生成一把」——那会让库里全部盲索引、名字
// 密文与配对索引集体失配，存量凭据按名不可达，等于数据丢失。
func TestLibraryKeyDoesNotOverwriteUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("JINTENG_DIR", dir)
	path := dir + string(os.PathSeparator) + LibraryKeyFile
	first, err := LibraryKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Skip("本环境无法制造不可读文件：", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	if _, err := LibraryKey(); err == nil {
		t.Fatal("库密钥不可读时必须报错，不得静默生成新钥匙")
	}
	again, err := os.ReadFile(path)
	if err != nil {
		_ = os.Chmod(path, 0600)
		again, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(again, first) {
		t.Error("原库密钥被覆写")
	}
}
