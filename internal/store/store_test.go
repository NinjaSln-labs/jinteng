package store

import (
	"os"
	"testing"

	"github.com/NinjaSln-labs/jinteng/internal/crypto"
)

func TestInitSetGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pw := "test-master-password"
	tok, err := Init(dir, pw)
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	v, err := Open(dir, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !v.CheckToken(tok) {
		t.Fatal("token hash mismatch")
	}
	if err := v.Set("a/b", "secret-value", "note"); err != nil {
		t.Fatal(err)
	}
	e, err := v.Get("a/b")
	if err != nil {
		t.Fatal(err)
	}
	if e.Value != "secret-value" || e.Note != "note" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if _, err := Open(dir, "wrong-password"); err == nil {
		t.Fatal("expected wrong password to fail")
	}
	fi, err := os.Stat(VaultPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("vault perms too open: %v", fi.Mode())
	}
}

func TestSealOpen(t *testing.T) {
	blob, err := crypto.Seal("pw", []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.Open("pw", blob)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != `{"ok":true}` {
		t.Fatalf("got %s", pt)
	}
}
