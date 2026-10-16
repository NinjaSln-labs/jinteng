package server

import (
	"net"
	"strings"
	"testing"
)

// TestSANIncludesListenIP 钉住这条的最后一句：自签证书的 SAN 必须并入实际监听
// 地址，否则跨机 TLS 握手在 pinning 之外还会撞主机名逻辑。
func TestSANIncludesListenIP(t *testing.T) {
	dns, ips, err := certSANHost("198.51.100.7:8787")
	if err != nil {
		t.Fatalf("certSANHost: %v", err)
	}
	var found bool
	for _, ip := range ips {
		if ip.Equal(net.ParseIP("198.51.100.7")) {
			found = true
		}
	}
	if !found {
		t.Errorf("SAN IP 不含监听地址: %v", ips)
	}
	if !contains(dns, "localhost") {
		t.Errorf("SAN DNS 应恒含 localhost，得 %v", dns)
	}
}

// TestSANIncludesListenHostname 主机名形式的监听地址进 DNSNames 而非 IPAddresses。
func TestSANIncludesListenHostname(t *testing.T) {
	dns, ips, err := certSANHost("jinteng.lan:8787")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(dns, "jinteng.lan") {
		t.Errorf("SAN DNS 不含监听主机名: %v", dns)
	}
	for _, ip := range ips {
		if ip.String() == "jinteng.lan" {
			t.Error("主机名被误当作 IP 写入 SAN")
		}
	}
}

// TestPrepareFailsWhenSANMismatchsListen 落实「pin 变更时 fail-closed」：既有证书
// 的 SAN 不含当前监听地址 ⇒ Prepare 报错并指向人工重签与重新核对指纹，
// 绝不自动重签（自动重签等于悄悄换掉所有端要吃的 pin）。
func TestPrepareFailsWhenSANMismatchsListen(t *testing.T) {
	e := newEnv(t)
	if err := e.srv.Prepare(); err != nil {
		t.Fatalf("首次 Prepare: %v", err)
	}
	e.srv.opts.Listen = "198.51.100.7:8787"
	err := e.srv.Prepare()
	if err == nil {
		t.Fatal("SAN 与监听地址不符时 Prepare 应报错（不自动重签）")
	}
	if !strings.Contains(err.Error(), "重新签发") || !strings.Contains(err.Error(), "指纹") {
		t.Errorf("错误应指向人工重签与重新 pin，得 %v", err)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
