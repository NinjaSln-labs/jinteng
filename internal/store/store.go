package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

const (
	DefaultDirName = ".jinteng"
	VaultFileName  = "jinteng.bin"
	TokenFileName  = "token"
	MetaVersion    = 1
)

var (
	ErrNotFound      = errors.New("secret not found")
	ErrAlreadyExists = errors.New("jinteng store already exists")
	ErrNotInit       = errors.New("jinteng not initialized; run: jinteng init")
)

type Entry struct {
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note,omitempty"`
}

type payload struct {
	Version    int               `json:"version"`
	TokenHash  string            `json:"token_hash"`
	Entries    map[string]Entry  `json:"entries"`
}

type Vault struct {
	mu       sync.Mutex
	path     string
	password string
	data     payload
}

func DefaultDir() (string, error) {
	if d := os.Getenv("JINTENG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultDirName), nil
}

func VaultPath(dir string) string {
	return filepath.Join(dir, VaultFileName)
}

func TokenPath(dir string) string {
	return filepath.Join(dir, TokenFileName)
}

func Init(dir, password string) (apiToken string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	vp := VaultPath(dir)
	if _, err := os.Stat(vp); err == nil {
		return "", ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	token, err := crypto.NewToken()
	if err != nil {
		return "", err
	}
	v := &Vault{
		path:     vp,
		password: password,
		data: payload{
			Version:   MetaVersion,
			TokenHash: crypto.HashToken(token),
			Entries:   map[string]Entry{},
		},
	}
	if err := v.saveLocked(); err != nil {
		return "", err
	}
	tp := TokenPath(dir)
	if err := os.WriteFile(tp, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func Open(dir, password string) (*Vault, error) {
	vp := VaultPath(dir)
	blob, err := os.ReadFile(vp)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInit
		}
		return nil, err
	}
	pt, err := crypto.Open(password, blob)
	if err != nil {
		return nil, err
	}
	var data payload
	if err := json.Unmarshal(pt, &data); err != nil {
		return nil, fmt.Errorf("jinteng decode: %w", err)
	}
	if data.Entries == nil {
		data.Entries = map[string]Entry{}
	}
	return &Vault{path: vp, password: password, data: data}, nil
}

func (v *Vault) CheckToken(token string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return crypto.HashToken(token) == v.data.TokenHash
}

func (v *Vault) RotateToken() (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	token, err := crypto.NewToken()
	if err != nil {
		return "", err
	}
	v.data.TokenHash = crypto.HashToken(token)
	if err := v.saveLocked(); err != nil {
		return "", err
	}
	return token, nil
}

func (v *Vault) Set(name, value, note string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data.Entries[name] = Entry{
		Value:     value,
		UpdatedAt: time.Now().UTC(),
		Note:      note,
	}
	return v.saveLocked()
}

func (v *Vault) Get(name string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.data.Entries[name]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return e, nil
}

func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.data.Entries[name]; !ok {
		return ErrNotFound
	}
	delete(v.data.Entries, name)
	return v.saveLocked()
}

type ListItem struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note,omitempty"`
}

func (v *Vault) List() []ListItem {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]ListItem, 0, len(v.data.Entries))
	for name, e := range v.data.Entries {
		out = append(out, ListItem{Name: name, UpdatedAt: e.UpdatedAt, Note: e.Note})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (v *Vault) Resolve(names []string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]string, len(names))
	for _, n := range names {
		e, ok := v.data.Entries[n]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, n)
		}
		out[n] = e.Value
	}
	return out, nil
}

func (v *Vault) saveLocked() error {
	pt, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	blob, err := crypto.Seal(v.password, pt)
	if err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func ReadLocalToken(dir string) (string, error) {
	b, err := os.ReadFile(TokenPath(dir))
	if err != nil {
		return "", err
	}
	return string(trimNL(b)), nil
}

func WriteLocalToken(dir, token string) error {
	return os.WriteFile(TokenPath(dir), []byte(token+"\n"), 0o600)
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
