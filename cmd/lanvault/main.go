package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sin/lanvault/internal/client"
	"github.com/sin/lanvault/internal/crypto"
	"github.com/sin/lanvault/internal/server"
	"github.com/sin/lanvault/internal/store"
	"golang.org/x/term"
)

const version = "0.1.0"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "help", "-h", "--help":
		usage()
	case "version", "-v", "--version":
		fmt.Println("lanvault", version)
	case "init":
		err = cmdInit(args)
	case "set":
		err = cmdSet(args)
	case "get":
		err = cmdGet(args)
	case "list", "ls":
		err = cmdList(args)
	case "delete", "rm":
		err = cmdDelete(args)
	case "run":
		err = cmdRun(args)
	case "serve":
		err = cmdServe(args)
	case "token":
		err = cmdToken(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`lanvault — encrypted secrets for local LAN / solo dev

Usage:
  lanvault init [--dir PATH]
  lanvault set <name> [--note TEXT] [value|-]
  lanvault get <name>
  lanvault list
  lanvault delete <name>
  lanvault run -e ENV=secretName ... -- <command...>
  lanvault serve [--listen ADDR]
  lanvault token show|rotate
  lanvault version

Env:
  LANVAULT_DIR       vault directory (default: ~/.lanvault)
  LANVAULT_PASSWORD  master password (prefer prompt / file in prod)
  LANVAULT_URL       if set, CLI talks to remote serve (e.g. http://192.168.1.10:8787)
  LANVAULT_TOKEN     API token for remote mode (default: $LANVAULT_DIR/token)

Never commit vault.bin, token, or plaintext .env files.
`)
}

func cmdInit(args []string) error {
	dir, _, err := parseDir(args)
	if err != nil {
		return err
	}
	pw, err := masterPassword(true)
	if err != nil {
		return err
	}
	token, err := store.Init(dir, pw)
	if err != nil {
		return err
	}
	fmt.Printf("initialized vault at %s\n", store.VaultPath(dir))
	fmt.Printf("API token written to %s (chmod 600)\n", store.TokenPath(dir))
	fmt.Printf("token: %s\n", token)
	fmt.Println("tip: export LANVAULT_PASSWORD only in a private shell; prefer interactive unlock for serve.")
	return nil
}

func cmdSet(args []string) error {
	name, note, rest, err := parseSetArgs(args)
	if err != nil {
		return err
	}
	var value string
	switch {
	case len(rest) == 0:
		fmt.Fprint(os.Stderr, "value: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		value = string(b)
	case rest[0] == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		value = strings.TrimRight(string(b), "\n\r")
	default:
		value = rest[0]
	}
	if value == "" {
		return errors.New("empty value")
	}

	if remote() {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		return c.Set(name, value, note)
	}
	v, err := openLocal()
	if err != nil {
		return err
	}
	return v.Set(name, value, note)
}

func cmdGet(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: lanvault get <name>")
	}
	name := args[0]
	if remote() {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		val, err := c.Get(name)
		if err != nil {
			return err
		}
		fmt.Print(val)
		if !strings.HasSuffix(val, "\n") {
			fmt.Println()
		}
		return nil
	}
	v, err := openLocal()
	if err != nil {
		return err
	}
	e, err := v.Get(name)
	if err != nil {
		return err
	}
	fmt.Print(e.Value)
	if !strings.HasSuffix(e.Value, "\n") {
		fmt.Println()
	}
	return nil
}

func cmdList(args []string) error {
	_ = args
	if remote() {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		items, err := c.List()
		if err != nil {
			return err
		}
		for _, it := range items {
			if it.Note != "" {
				fmt.Printf("%s\t%s\n", it.Name, it.Note)
			} else {
				fmt.Println(it.Name)
			}
		}
		return nil
	}
	v, err := openLocal()
	if err != nil {
		return err
	}
	for _, it := range v.List() {
		if it.Note != "" {
			fmt.Printf("%s\t%s\n", it.Name, it.Note)
		} else {
			fmt.Println(it.Name)
		}
	}
	return nil
}

func cmdDelete(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: lanvault delete <name>")
	}
	name := args[0]
	if remote() {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		return c.Delete(name)
	}
	v, err := openLocal()
	if err != nil {
		return err
	}
	return v.Delete(name)
}

func cmdRun(args []string) error {
	envMaps, cmdArgs, err := parseRunArgs(args)
	if err != nil {
		return err
	}
	if len(cmdArgs) == 0 {
		return errors.New("usage: lanvault run -e ENV=secretName ... -- <command>")
	}

	names := make([]string, 0, len(envMaps))
	for _, n := range envMaps {
		names = append(names, n)
	}

	var values map[string]string
	if remote() {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		values, err = c.Resolve(names)
		if err != nil {
			return err
		}
	} else {
		v, err := openLocal()
		if err != nil {
			return err
		}
		values, err = v.Resolve(names)
		if err != nil {
			return err
		}
	}

	env := os.Environ()
	for envKey, secretName := range envMaps {
		env = append(env, envKey+"="+values[secretName])
	}

	c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func cmdServe(args []string) error {
	listen := "127.0.0.1:8787"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--listen", "-l":
			i++
			if i >= len(args) {
				return errors.New("--listen needs address")
			}
			listen = args[i]
		case "--dir":
			i++
			if i >= len(args) {
				return errors.New("--dir needs path")
			}
			dir = args[i]
		case "--lan":
			listen = "0.0.0.0:8787"
		default:
			return fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	if dir == "" {
		var err error
		dir, err = store.DefaultDir()
		if err != nil {
			return err
		}
	}
	pw, err := masterPassword(false)
	if err != nil {
		return err
	}
	v, err := store.Open(dir, pw)
	if err != nil {
		return err
	}
	s := &server.Server{Vault: v, Logger: log.Default()}
	return s.ListenAndServe(listen)
}

func cmdToken(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: lanvault token show|rotate")
	}
	dir, err := store.DefaultDir()
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		t, err := store.ReadLocalToken(dir)
		if err != nil {
			return err
		}
		fmt.Println(t)
		return nil
	case "rotate":
		if remote() {
			return errors.New("token rotate must run on the vault host (local mode)")
		}
		v, err := openLocal()
		if err != nil {
			return err
		}
		tok, err := v.RotateToken()
		if err != nil {
			return err
		}
		if err := store.WriteLocalToken(dir, tok); err != nil {
			return err
		}
		fmt.Println(tok)
		return nil
	default:
		return fmt.Errorf("unknown token subcommand: %s", args[0])
	}
}

func remote() bool {
	return os.Getenv("LANVAULT_URL") != ""
}

func remoteClient() (*client.Client, error) {
	url := os.Getenv("LANVAULT_URL")
	tok := os.Getenv("LANVAULT_TOKEN")
	if tok == "" {
		dir, err := store.DefaultDir()
		if err != nil {
			return nil, err
		}
		tok, err = store.ReadLocalToken(dir)
		if err != nil {
			return nil, fmt.Errorf("LANVAULT_TOKEN not set and cannot read local token: %w", err)
		}
	}
	return client.New(url, tok), nil
}

func openLocal() (*store.Vault, error) {
	dir, err := store.DefaultDir()
	if err != nil {
		return nil, err
	}
	pw, err := masterPassword(false)
	if err != nil {
		return nil, err
	}
	return store.Open(dir, pw)
}

func masterPassword(confirm bool) (string, error) {
	if pw := os.Getenv("LANVAULT_PASSWORD"); pw != "" {
		return pw, nil
	}
	if path := os.Getenv("LANVAULT_PASSWORD_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(trimNL(b)), nil
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		// non-interactive bootstrap helper
		if confirm {
			pw, err := crypto.RandomPassword()
			if err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "generated master password (save it): %s\n", pw)
			return pw, nil
		}
		return "", errors.New("set LANVAULT_PASSWORD or LANVAULT_PASSWORD_FILE (stdin is not a TTY)")
	}
	fmt.Fprint(os.Stderr, "master password: ")
	b1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	pw := string(b1)
	if pw == "" {
		return "", errors.New("empty password")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "confirm password: ")
		b2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if pw != string(b2) {
			return "", errors.New("passwords do not match")
		}
	}
	return pw, nil
}

func parseDir(args []string) (dir string, rest []string, err error) {
	dir, err = store.DefaultDir()
	if err != nil {
		return "", nil, err
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" {
			i++
			if i >= len(args) {
				return "", nil, errors.New("--dir needs path")
			}
			dir = args[i]
			continue
		}
		rest = append(rest, args[i])
	}
	return dir, rest, nil
}

func parseSetArgs(args []string) (name, note string, rest []string, err error) {
	if len(args) < 1 {
		return "", "", nil, errors.New("usage: lanvault set <name> [--note TEXT] [value|-]")
	}
	name = args[0]
	i := 1
	for i < len(args) {
		if args[i] == "--note" {
			i++
			if i >= len(args) {
				return "", "", nil, errors.New("--note needs text")
			}
			note = args[i]
			i++
			continue
		}
		break
	}
	rest = args[i:]
	return name, note, rest, nil
}

func parseRunArgs(args []string) (map[string]string, []string, error) {
	envMaps := map[string]string{}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if a == "-e" || a == "--env" {
			i++
			if i >= len(args) {
				return nil, nil, errors.New("-e needs ENV=secretName")
			}
			k, v, ok := strings.Cut(args[i], "=")
			if !ok || k == "" || v == "" {
				return nil, nil, fmt.Errorf("invalid -e mapping: %s", args[i])
			}
			envMaps[k] = v
			i++
			continue
		}
		// allow trailing command without -- if first non-flag looks like a binary
		break
	}
	cmdArgs := args[i:]
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}
	return envMaps, cmdArgs, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
