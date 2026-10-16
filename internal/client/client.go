// Package client 是本端取用面：双要素解锁（口令 ‖ 机器指纹）后的 Session 提供
// Put/Take/Run/Revoke，全部经服务端 HTTP 面（TLS 指纹 pinning），凭据明文只在
// 本端内存与子进程 env 中出现，绝不落盘、绝不进 error 文本、绝不进事件。
//
// 密钥生命周期：X25519 私钥与 Ed25519 签名 seed 只在 Unlock 成功
// 后存在于 Session，Close 即两把都清零；每条 Take 现场 UnwrapDEK 出临时 DEK，
// 解完立即清零；Run 返回后不保留任何工作密钥。本包不做任何跨命令缓存。
package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/audit"
	"github.com/NinjaSln-labs/jinteng/internal/crypto"
	"github.com/NinjaSln-labs/jinteng/internal/material"
	"github.com/NinjaSln-labs/jinteng/internal/server"
	"github.com/NinjaSln-labs/jinteng/internal/sign"
)

// 可区分错误哨兵（2.4）。按服务端响应体里的 error 码字符串映射，不看 status：
// unauthorized-device→ErrUnauthDevice，revoked→ErrRevoked，
// wrap-missing→ErrWrapMissing（名存在但该端无副本，不是被撤销），
// not-found→ErrNotFound。ErrAuditFailed 供 CLI 如实提示 500 语义
// （store 变更可能已提交、事件未落，不得报成回滚）。
var (
	ErrUnreachable  = errors.New("client: 服务端不可达;本产品不提供缓存值")
	ErrUnauthDevice = errors.New("client: 设备未获服务端授权")
	ErrNotFound     = errors.New("client: 凭据名不存在")
	ErrRevoked      = errors.New("client: 设备已撤销")
	ErrWrapMissing  = errors.New("client: 该端无此名的 wrap 副本")
	ErrAuditFailed  = errors.New("client: 服务端事件写入失败")
)

// envNamePattern 是 run 注入变量名的最小校验（信任边界输入）。
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// controlEnvPrefix 是本程序控制面环境变量的名字前缀，覆盖 JINTENG_DIR／
// JINTENG_PASSFILE／JINTENG_PASSENV／JINTENG_FP_OVERRIDE_DIR。Run 从交给
// 子进程的 env 副本里按前缀剔除它们（见 Run）。
const controlEnvPrefix = "JINTENG_"

// deviceIDPattern 是本端设备 id 的字符规则（进入 URL query，须无转义面）。
var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Config 是 Dir()/config.json 的形状：只含结构性材料。
// v2 起这里不再有设备注册表——名录的唯一事实源在服务端;
// 写入端每次 Put 现查名录，因此「注册表外在册端拿不到新 DEK」这条缺口闭合。
type Config struct {
	ServerURL string `json:"server_url"`
	TLSPin    string `json:"tls_pin"`
	DeviceID  string `json:"device_id"`
}

func saveConfig(cfg Config) error {
	data, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return errors.New("client: 配置序列化失败")
	}
	return material.SaveAs(material.ConfigFile, append(data, '\n'), 0600)
}

func loadConfig() (Config, error) {
	var cfg Config
	dir, err := material.Dir()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(dir + string(os.PathSeparator) + material.ConfigFile)
	if err != nil {
		return cfg, errors.New("client: 无法读取客户端配置（先执行 jinteng init）")
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, errors.New("client: 客户端配置格式非法")
	}
	if cfg.ServerURL == "" || cfg.DeviceID == "" {
		return cfg, errors.New("client: 客户端配置缺字段")
	}
	if !deviceIDPattern.MatchString(cfg.DeviceID) {
		return cfg, errors.New("client: 配置中的设备 id 非法（规则 [A-Za-z0-9_.-]{1,64}）")
	}
	// 方案锁死 https：明文 HTTP 没有证书，newHTTPClient 的 VerifyPeerCertificate
	// pinning 根本不参与，凭据名与 device id 会明文上网。只在 Init 校验过一次不够——
	// config.json 可被手改或换成坏值，真正出网前读它的这里必须自己把关。
	if !strings.HasPrefix(cfg.ServerURL, "https://") {
		return cfg, errors.New("client: 配置中的服务端 URL 必须以 https:// 开头（明文 HTTP 会绕过 TLS 指纹 pinning）")
	}
	return cfg, nil
}

// newHTTPClient 构造带 TLS 指纹 pinning 的客户端：证书链自签无信任根，
// 唯一信任锚是 init 时人工录入、存于 Config.TLSPin 的 SHA-256 指纹
// （与 server.Prepare 首次生成打印的口径一致：hex(sha256(cert DER))）。
// 不校验指纹等于 TLS 退化——这里没有可关闭该校验的路径。
//
// ponytail: trust-on-register，无自动轮换；提升点在配对流程。
func newHTTPClient(pin string) (*http.Client, error) {
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("client: TLS pin 非法（需 64 位十六进制 SHA-256 指纹）")
	}
	hexWant := strings.ToLower(hex.EncodeToString(want))
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// 自签证书没有可验证的链；固定叶子证书 SHA-256 是唯一裁判。
				InsecureSkipVerify: true, //nolint:gosec // 由 VerifyPeerCertificate 手动 pin 替代
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					for _, raw := range rawCerts {
						sum := sha256.Sum256(raw)
						if hex.EncodeToString(sum[:]) == hexWant {
							return nil
						}
					}
					return errors.New("client: 服务端证书与固定指纹不符，拒绝连接")
				},
			},
		},
	}, nil
}

// responseError 把非 2xx 响应映射为可区分错误：只看响应体 error 码字符串，
// 不看 HTTP status（403 有 revoked 与 wrap-missing 两个码）。错误文本只含码。
func responseError(status int, body []byte) error {
	var m struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &m)
	switch m.Error {
	case "unknown-device", "unauthorized-device":
		return fmt.Errorf("%w（服务端码 unknown-device）", ErrUnauthDevice)
	case "revoked", "device-revoked":
		return fmt.Errorf("%w（服务端码 device-revoked）", ErrRevoked)
	case "bad-signature", "stale-request", "replayed", "invalid-pair-code":
		return fmt.Errorf("client: 服务端拒绝（码 %s）", m.Error)
	case "wrap-missing":
		return fmt.Errorf("%w（服务端码 wrap-missing）", ErrWrapMissing)
	case "not-found":
		return fmt.Errorf("%w（服务端码 not-found）", ErrNotFound)
	case "audit-failed":
		return fmt.Errorf("%w：操作可能已生效，只是事件未能记录；重试语义：put/revoke 幂等,enroll 的配对码与落库同事务提交,故重试会因码已消费报 invalid-pair-code（需重新签发一枚码）", ErrAuditFailed)
	case "device-exists":
		return errors.New("client: 该设备 id 已在服务端登记（若此前遇到 audit-failed，这是重试的预期结果——设备已注册成功）")
	case "":
		return fmt.Errorf("client: 服务端拒绝（HTTP %d，无错误码）", status)
	default:
		return fmt.Errorf("client: 服务端拒绝（码 %s）", m.Error)
	}
}

// errorFromResp 读取响应体（≤64 KiB）并映射为错误。
func errorFromResp(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return responseError(resp.StatusCode, body)
}

// Session 是一次解锁后的取用会话：两把私钥只活在这里，Close 即弃。
type Session struct {
	cfg     Config
	hc      *http.Client
	dhPriv  []byte // 解封后的 X25519 设备私钥（32 B），Close 清零
	sigSeed []byte // 解封后的 Ed25519 签名 seed（32 B），Close 清零
}

// Unlock 读取 config.json 与 device.key，按 TTY > JINTENG_PASSFILE >
// JINTENG_PASSENV 取口令，结合本机指纹解封设备密钥（加密私钥与签名私钥）。
// 纯本机操作＋本地校验，不联网（未登记端也允许解锁，取用时由服务端拒绝）。
// 错误文本不含口令、指纹或私钥内容。
func Unlock() (*Session, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	pass, err := readPassphrase()
	if err != nil {
		return nil, err
	}
	fprint, err := currentFingerprint()
	if err != nil {
		return nil, err
	}
	dhPriv, sigSeed, err := material.LoadKeys(pass, fprint)
	if err != nil {
		return nil, err
	}
	hc, err := newHTTPClient(cfg.TLSPin)
	if err != nil {
		clear(dhPriv)
		clear(sigSeed)
		return nil, err
	}
	return &Session{cfg: cfg, hc: hc, dhPriv: dhPriv, sigSeed: sigSeed}, nil
}

// Close 清零会话持有的两把私钥；此后该 Session 不可再用。
func (s *Session) Close() {
	clear(s.dhPriv)
	clear(s.sigSeed)
	s.dhPriv, s.sigSeed = nil, nil
}

func (s *Session) locked() error {
	if s.dhPriv == nil || s.sigSeed == nil {
		return errors.New("client: 会话已关闭")
	}
	return nil
}

// do 发送一个 v2 签名请求：规范串 → 时间戳与 nonce → 签名 → 四件头送出。
// 传输层失败一律映射为 ErrUnreachable（不给旧值，明确失败）。
func (s *Session) do(method, path string, query url.Values, body []byte) (*http.Response, error) {
	return doSigned(s.hc, s.cfg.ServerURL, s.cfg.DeviceID, s.sigSeed, method, path, query, body)
}

// doSigned 是签名请求的单点实现（Session 与 Init 的登记路径共用，杜绝两种写法）。
func doSigned(hc *http.Client, base, deviceID string, seed []byte,
	method, path string, query url.Values, body []byte) (*http.Response, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("client: 随机数读取失败")
	}
	h := sign.Header{Device: deviceID, Ts: time.Now().Unix(), Nonce: base64.StdEncoding.EncodeToString(nonce)}
	if err := sign.Sign(seed, &h, sign.CanonicalWithHeaders(h, method, path, query, body)); err != nil {
		return nil, errors.New("client: 请求签名失败")
	}
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("client: 请求构造失败")
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Jinteng-Device", h.Device)
	req.Header.Set("X-Jinteng-Ts", strconv.FormatInt(h.Ts, 10))
	req.Header.Set("X-Jinteng-Nonce", h.Nonce)
	req.Header.Set("X-Jinteng-Sig", h.Sig)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: 请求发不出（%s）", ErrUnreachable, path)
	}
	return resp, nil
}

// directoryEntry 是服务端名录的一条（id／撤销位／两把公钥）。
type directoryEntry struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
	DhPub   string `json:"dh_pub"`
	SigPub  string `json:"sig_pub"`
}

// directory 现查服务端名录：本端不再有注册表，写入端因此能看到
// 「从未在本地登记过」的在册端。
func (s *Session) directory() ([]directoryEntry, error) {
	resp, err := s.do("GET", "/v2/devices", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResp(resp)
	}
	var m struct {
		Devices []directoryEntry `json:"devices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, errors.New("client: 名录响应格式非法")
	}
	return m.Devices, nil
}

// Put 密封并写入一条凭据：每条一个随机 DEK；同名覆盖＝新 DEK 重新 Seal＋
// 对名录里全部未撤销端重新 WrapDEK，旧密文与旧 wrap 集合被整体替换
// （这是「轮换后旧端解不出新值」的地基）。
// 非法名在任何写入（含网络请求）之前拒绝。error 不含值内容。
func (s *Session) Put(name, value string) error {
	if err := s.locked(); err != nil {
		return err
	}
	if err := server.ValidName(name); err != nil {
		return errors.New("client: 非法凭据名（规则 [A-Za-z0-9_]{1,64}，拒绝发生在任何写入之前）")
	}
	dek, err := crypto.NewDEK()
	if err != nil {
		return err
	}
	defer clear(dek)
	ct, err := crypto.SealValue(dek, []byte(value))
	if err != nil {
		return err
	}
	devices, err := s.directory()
	if err != nil {
		return err
	}
	wraps := make(map[string]string, len(devices))
	for _, d := range devices {
		if d.Revoked {
			continue // 撤销端不再发新 wrap（停止为其下发）
		}
		pub, err := base64.StdEncoding.DecodeString(d.DhPub)
		if err != nil {
			return fmt.Errorf("client: 名录中设备 %q 的公钥非法", d.ID)
		}
		w, err := crypto.WrapDEK(dek, pub)
		if err != nil {
			return fmt.Errorf("client: wrap 设备 %q 失败", d.ID)
		}
		wraps[d.ID] = base64.StdEncoding.EncodeToString(w)
	}
	payload, err := json.Marshal(map[string]any{
		"name":       name,
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
		"wraps":      wraps,
	})
	if err != nil {
		return errors.New("client: 请求序列化失败")
	}
	resp, err := s.do("POST", "/v2/secret", nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errorFromResp(resp)
	}
	return nil
}

// Take 取回一条凭据明文：GET 密文信封与该端 wrap → 本机解封。
// 四类拒绝可用 errors.Is 区分（哨兵映射见 responseError）。
// 明文只返回给调用方，本函数不留任何副本。
func (s *Session) Take(name string) ([]byte, error) {
	if err := s.locked(); err != nil {
		return nil, err
	}
	if err := server.ValidName(name); err != nil {
		return nil, errors.New("client: 非法凭据名（规则 [A-Za-z0-9_]{1,64}）")
	}
	resp, err := s.do("GET", "/v2/secret/"+name, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResp(resp)
	}
	var m struct {
		Ciphertext string `json:"ciphertext"`
		Wrap       string `json:"wrap"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, errors.New("client: 取用响应格式非法")
	}
	ct, err := base64.StdEncoding.DecodeString(m.Ciphertext)
	if err != nil {
		return nil, errors.New("client: 取用响应密文非法")
	}
	wrap, err := base64.StdEncoding.DecodeString(m.Wrap)
	if err != nil {
		return nil, errors.New("client: 取用响应 wrap 非法")
	}
	dek, err := crypto.UnwrapDEK(wrap, s.dhPriv)
	if err != nil {
		return nil, errors.New("client: 解封 DEK 失败")
	}
	defer clear(dek)
	plain, err := crypto.OpenValue(dek, ct)
	if err != nil {
		return nil, errors.New("client: 解密凭据值失败")
	}
	return plain, nil
}

// actionRun 是客户端面独有的取用事件（服务端四路由不使用 run；属事件动作枚举）。
const actionRun = "run"

// Run 按 envMapping（子进程变量名→凭据名）取用并注入，然后启动 argv。
// 值只进子进程 env，绝不落盘；每条成功注入写一条 run 事件（blind index
// 复用 server.BlindIndex，明名不进事件）。run 事件写不进时不启动子进程
// （客户端面对「可观测性承诺」同样 fail-closed，与服务端 500 语义呼应）。
// 交给子进程的 env 是「继承 env 去掉 JINTENG_ 前缀的控制面变量＋注入项」：
// 解封口令（JINTENG_PASSENV）与材料目录／指纹覆录钩子一概不外传：注入方与
// 被注入命令都不得依赖这些变量，需要路径时由 argv 显式传。
// 返回子进程退出码：0-125 透传；被信号杀死按 128+signal（unix 惯例）。
// 子进程非零退出不是 error；只有本面/用法失败才返回 error。
//
// ponytail: env 注入的字符串值在进程内等 GC 才消失（Go 字符串不可变，无法
// 就地清零）；上限＝本进程存活期，与「Session 之外无缓存」承诺一致，升级
// 路径是改用 syscall.Exec 直接替换进程。
func (s *Session) Run(envMapping map[string]string, argv []string) (int, error) {
	if err := s.locked(); err != nil {
		return 0, err
	}
	if len(argv) == 0 {
		return 0, errors.New("client: run 缺少被调用命令")
	}
	envNames := make([]string, 0, len(envMapping))
	for k := range envMapping {
		envNames = append(envNames, k)
	}
	sort.Strings(envNames)

	// 继承来的 env 副本先剔除本程序的控制面变量（按名字前缀，比逐条列举稳）：
	// JINTENG_PASSENV 的值就是解封口令本身，自动化／e2e 场景不设它就拿不到口令，
	// 原样继承等于让每条 `run` 的第三方命令及其全部衍生进程读到口令——这超出
	// 注入值这条的已知天花板（讲的是凭据值注入，不是口令）。JINTENG_DIR／
	// JINTENG_PASSFILE／JINTENG_FP_OVERRIDE_DIR 同属本程序控制面，一并剔除。
	// 剔除只作用于继承项：下面的凭据注入照常追加，包括变量名恰好以 JINTENG_
	// 开头的注入项。
	env := make([]string, 0, len(os.Environ()))
	// run 事件的盲索引与服务端同源（同一把 library.key，N6①）。本端与服务端
	// 同目录时索引一致；异端事件的盲索引只服务该端本地事件面，窗口达标判定的计数
	// 走服务端 get 事件，不依赖它。
	libKey, err := material.LibraryKey()
	if err != nil {
		return 0, err
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, controlEnvPrefix) {
			continue
		}
		env = append(env, kv)
	}
	for _, envName := range envNames {
		credName := envMapping[envName]
		if !envNamePattern.MatchString(envName) || server.ValidName(credName) != nil {
			return 0, errors.New("client: run 映射非法（变量名或凭据名不合规则）")
		}
		v, err := s.Take(credName)
		if err != nil {
			return 0, err
		}
		blind, err := server.BlindIndex(libKey, credName)
		if err != nil {
			return 0, errors.New("client: run 事件盲索引派生失败")
		}
		if err := audit.Write(audit.Event{
			TS: time.Now(), DeviceID: s.cfg.DeviceID, Action: actionRun,
			Outcome: "ok", NameBlindIndex: blind,
		}); err != nil {
			return 0, fmt.Errorf("client: run 事件写入失败，未启动子进程（fail-closed）: %w", err)
		}
		env = append(env, envName+"="+string(v))
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	cmd.Env = nil // 释放对明文 env 的引用，等 GC 回收

	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// 信号死亡按 128+signal；类型断言走接口，跨平台不新增构建分支。
		type signaledStatus interface {
			Signaled() bool
			Signal() syscall.Signal
		}
		if ws, ok := ee.ProcessState.Sys().(signaledStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil // 非零退出如实透传，不算本面错误
	}
	return 0, errors.New("client: 子进程启动失败")
}

// Revoke 撤销本端（置服务端状态位，O(1)，不重包任何密文）。
// 撤销是取用面的即时封锁：重复撤销幂等。若该端用**同一对密钥**重新登记,撤销位被清
// 且旧 wrap 仍可解开（不重包语义的直接后果）;要彻底断绝内容仍需轮换凭据或改用新密钥对。
// 发起面：只接受撤销自己那端——服务端同样强制；撤他端属
// 服务端操作员动作,在 serve 终端管理通道里做。这里在任何出网之前就拒。
func (s *Session) Revoke(deviceID string) error {
	if err := s.locked(); err != nil {
		return err
	}
	if deviceID == "" {
		return errors.New("client: 缺少设备 id")
	}
	if deviceID != s.cfg.DeviceID {
		return fmt.Errorf("client: 客户端只能撤销自己那端（本端 %q,被请求撤销 %q）;"+
			"撤他端请在 serve 终端输入「revoke <device_id>」", s.cfg.DeviceID, deviceID)
	}
	payload, _ := json.Marshal(map[string]string{"device_id": deviceID})
	resp, err := s.do("POST", "/v2/device/revoke", nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errorFromResp(resp)
	}
	return nil
}

// Init 建立本端静息材料并向服务端登记：新设备密钥对（加密＋签名）、口令‖指纹
// 封存、写 config.json、POST /v2/enroll。口令只在场一次——登记用的签名密钥就在
// 手里，不需要二次解锁。
// deviceID 为空时自动生成；已存在 device.key 或 config.json 时拒绝覆盖
// （误删即永久自锁，v0 无恢复机制）。空口令一律拒绝封存——否则 device.key
// 降为指纹单要素，违背 spec「该口令与机器指纹共同生效」的两要素承诺。
// 登记必须由一次性配对码授权：缺码在任何出网之前拒绝。
func Init(serverURL, pin, deviceID, pairCode string) error {
	if pairCode == "" {
		return errors.New("client: init 缺少配对码（登记须由服务端 jinteng pair new 签发的一次性码授权）")
	}
	raw, err := hex.DecodeString(pin)
	if err != nil || len(raw) != sha256.Size || !strings.HasPrefix(serverURL, "https://") {
		return errors.New("client: init 参数非法（url 须 https://，pin 须 64 位十六进制指纹）")
	}
	if deviceID == "" {
		rb := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, rb); err != nil {
			return errors.New("client: 随机设备 id 生成失败")
		}
		deviceID = "dev-" + hex.EncodeToString(rb)
	}
	if !deviceIDPattern.MatchString(deviceID) {
		return errors.New("client: 非法设备 id（规则 [A-Za-z0-9_.-]{1,64}）")
	}
	dir, err := material.Dir()
	if err != nil {
		return err
	}
	for _, f := range []string{material.DeviceKeyFile, material.ConfigFile} {
		if _, err := os.Stat(dir + string(os.PathSeparator) + f); err == nil {
			return fmt.Errorf("client: 静息材料 %s 已存在，拒绝覆盖（v0 无恢复机制）", f)
		}
	}
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	if pass == "" {
		return errors.New("client: 空口令被拒绝（封存须口令与机器指纹共同生效）")
	}
	fprint, err := currentFingerprint()
	if err != nil {
		return err
	}
	dhPub, dhPriv, err := crypto.NewDevice()
	if err != nil {
		return err
	}
	defer clear(dhPriv)
	sigPub, sigSeed, err := crypto.NewSignKey()
	if err != nil {
		return err
	}
	defer clear(sigSeed)
	blob, err := crypto.SealDeviceKeys(dhPriv, sigSeed, pass, fprint)
	if err != nil {
		return err
	}
	if err := material.Save(blob, 0600); err != nil {
		return err
	}
	if err := saveConfig(Config{ServerURL: serverURL, TLSPin: pin, DeviceID: deviceID}); err != nil {
		return err
	}
	if err := enroll(serverURL, pin, deviceID, pairCode, dhPub, sigPub, sigSeed); err != nil {
		return fmt.Errorf("client: 材料已建立，但登记未确认: %w", err)
	}
	return nil
}

// enroll 用刚生成的签名密钥自证这次登记（「验签即验证」）。
// 500 audit-failed 后重试需要一枚新配对码（旧码已消费），该码单独提示。
func enroll(serverURL, pin, deviceID, pairCode string, dhPub, sigPub, seed []byte) error {
	hc, err := newHTTPClient(pin)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"device_id": deviceID,
		"dh_pub":    base64.StdEncoding.EncodeToString(dhPub),
		"sig_pub":   base64.StdEncoding.EncodeToString(sigPub),
		"pair_code": pairCode,
	})
	resp, err := doSigned(hc, serverURL, deviceID, seed, "POST", "/v2/enroll", nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return errorFromResp(resp)
}
