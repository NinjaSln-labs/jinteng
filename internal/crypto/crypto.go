package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	Magic      = "LVLT1"
	SaltSize   = 16
	NonceSize  = 12
	KeySize    = 32
	argonTime  = 3
	argonMem   = 64 * 1024
	argonThreads = 4
)

var ErrWrongPassword = errors.New("wrong master password or corrupted vault")

// Seal encrypts plaintext with a key derived from password+salt.
// Layout: magic | salt | nonce | ciphertext
func Seal(password string, plaintext []byte) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(Magic)+SaltSize+NonceSize+len(ct))
	out = append(out, Magic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a sealed blob.
func Open(password string, blob []byte) ([]byte, error) {
	min := len(Magic) + SaltSize + NonceSize + 16
	if len(blob) < min {
		return nil, errors.New("vault file too short")
	}
	if string(blob[:len(Magic)]) != Magic {
		return nil, errors.New("not a lanvault file")
	}
	off := len(Magic)
	salt := blob[off : off+SaltSize]
	off += SaltSize
	nonce := blob[off : off+NonceSize]
	off += NonceSize
	ct := blob[off:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonThreads, KeySize)
}

// HashToken returns a short fingerprint for storing/comparing API tokens.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

// NewToken creates a URL-safe random token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("lv_%x", b), nil
}

// RandomPassword generates a strong passphrase for non-interactive bootstrap.
func RandomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
