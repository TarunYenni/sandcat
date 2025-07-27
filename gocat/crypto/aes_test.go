package crypto_test

import (
	"bytes"
	"testing"

	"github.com/mitre/gocat/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("secret message")
	cipherText, err := crypto.EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	decrypted, err := crypto.DecryptAES(key, cipherText)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("data")
	cipherText, err := crypto.EncryptAES(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	wrongKey := []byte("fedcba9876543210")
	if _, err = crypto.DecryptAES(wrongKey, cipherText); err == nil {
		t.Errorf("expected error when decrypting with wrong key")
	}
}
