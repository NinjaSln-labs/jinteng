package server

// TLS 材料：自签证书与私钥落在 material.Dir() 下的
// server.crt / server.key——两者已纳入 material.Inventory()，是静息材料，
// 异机口径的枚举面必须看得见。私钥经 material.SaveAs 落盘，权限裁决与
// device.key 同源（>0600 直接拒绝，不另写 chmod）。
// 首次生成时向 opts.Out 打印证书 SHA-256 指纹供客户端 pinning——打印的
// 只有指纹（哈希），绝不输出证书私钥或任何凭据值。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/material"
)

// Prepare 幂等确保 TLS 材料就位并记录路径。证书与私钥同时存在则复用，但复用前
// 必须核对 SAN 覆盖当前监听地址：不符即报错并指向人工重签与重新核对指纹（pin）,
// 不提供自动重签——自动换证书等于悄悄换掉每一端要吃的 pin，故这里 fail-closed。
// 首次生成打印指纹到 opts.Out。
func (s *Server) Prepare() error {
	dir, err := material.Dir()
	if err != nil {
		return err
	}
	certPath := filepath.Join(dir, material.ServerCertFile)
	keyPath := filepath.Join(dir, material.ServerKeyFile)
	if fileExists(certPath) && fileExists(keyPath) {
		if err := certCoversListen(certPath, s.opts.Listen); err != nil {
			return err
		}
		s.certPath, s.keyPath = certPath, keyPath
		return nil
	}
	der, err := genSelfSigned(s.opts.Listen)
	if err != nil {
		return err
	}
	s.certPath, s.keyPath = certPath, keyPath
	// 只打印指纹：客户端 pinning 用；私钥只落盘不上屏。
	sum := sha256.Sum256(der)
	fmt.Fprintf(s.opts.Out, "jinteng TLS 证书已生成，指纹 (SHA-256): %x\n", sum)
	return nil
}

// certSANHost 派生证书 SAN：恒含回环三件，并把实际监听 host 并入（IP 进
// IPAddresses、主机名进 DNSNames）。否则跨机 TLS 握手在 pinning 之外还会撞
// 主机名逻辑。
func certSANHost(listen string) (dns []string, ips []net.IP, err error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, nil, errors.New("server: 非法监听地址")
	}
	dns = []string{"localhost"}
	ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if host == "" {
		return nil, nil, errors.New("server: 监听地址缺 host")
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, existing := range ips {
			if existing.Equal(ip) {
				return dns, ips, nil
			}
		}
		return dns, append(ips, ip), nil
	}
	return append(dns, host), ips, nil
}

// certCoversListen 校验既有证书的 SAN 是否含当前监听 host。
func certCoversListen(certPath, listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host == "" {
		return errors.New("server: 监听地址非法，无法核对证书 SAN")
	}
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return errors.New("server: 无法读取既有证书")
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("server: 既有证书格式非法")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("server: 既有证书解析失败")
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, existing := range cert.IPAddresses {
			if existing.Equal(ip) {
				return nil
			}
		}
	} else {
		for _, name := range cert.DNSNames {
			if name == host {
				return nil
			}
		}
	}
	return fmt.Errorf("server: 既有证书 SAN 不含监听地址 %q;本产品不自动换证书——请人工删除 %s／%s 重新签发，并在各端重新核对并固定指纹（pin）",
		host, material.ServerCertFile, material.ServerKeyFile)
}

// genSelfSigned 生成 ECDSA P-256 自签证书（SAN 按 listen 派生,见 certSANHost）,
// 经 material.SaveAs 落盘（权限裁决单点,≤0600）,返回证书 DER（供算指纹）。
// ponytail: 有效期 10 年、无自动轮换——轮换需要人在场重新核对 pin。
func genSelfSigned(listen string) ([]byte, error) {
	dnsNames, ipAddrs, err := certSANHost(listen)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("server: 生成 TLS 私钥失败")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("server: 生成证书序列号失败")
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "jinteng-local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // 自签：主体即签发者
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("server: 自签证书生成失败")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("server: TLS 私钥序列化失败")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// 私钥与证书都走 material 权限裁决（≤0600，异机取证口径视角都是静息材料）。
	if err := material.SaveAs(material.ServerKeyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("server: TLS 私钥落盘失败")
	}
	if err := material.SaveAs(material.ServerCertFile, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("server: 证书落盘失败")
	}
	return der, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
