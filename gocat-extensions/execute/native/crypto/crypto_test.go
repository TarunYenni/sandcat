package crypto

import (
	"encoding/base64"
	"testing"

	gocrypto "github.com/mitre/gocat/crypto"
	"github.com/mitre/gocat/execute/native/testutil"
	"github.com/mitre/gocat/execute/native/util"
)

func TestEncryptDecryptData(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("hello")
	keyB64 := base64.StdEncoding.EncodeToString(key)
	plainB64 := base64.StdEncoding.EncodeToString(plaintext)

	encRes := EncryptData([]string{keyB64, plainB64})
	if encRes.ExitCode != util.SUCCESS_EXIT_CODE {
		t.Fatalf("encrypt failed: %s", string(encRes.Stderr))
	}
	cipherText, err := base64.StdEncoding.DecodeString(string(encRes.Stdout))
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	// Decrypt using the native method
	cipherB64 := base64.StdEncoding.EncodeToString(cipherText)
	decRes := DecryptData([]string{keyB64, cipherB64})
	if decRes.ExitCode != util.SUCCESS_EXIT_CODE {
		t.Fatalf("decrypt failed: %s", string(decRes.Stderr))
	}
	outBytes, err := base64.StdEncoding.DecodeString(string(decRes.Stdout))
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if string(outBytes) != string(plaintext) {
		t.Errorf("expected %s, got %s", plaintext, outBytes)
	}
}

func TestEncryptDataBadArgs(t *testing.T) {
	res := EncryptData([]string{"onlyonearg"})
	testutil.VerifyResult(t, res, "", argErrMsg, argErrMsg)
}

func TestDecryptDataBadArgs(t *testing.T) {
	res := DecryptData([]string{})
	testutil.VerifyResult(t, res, "", argErrMsg, argErrMsg)
}

func TestDecryptDataWrongKey(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("secret")
	cipherText, _ := gocrypto.EncryptAES(key, plaintext)
	cipherB64 := base64.StdEncoding.EncodeToString(cipherText)
	wrongKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	res := DecryptData([]string{wrongKey, cipherB64})
	if res.ExitCode != util.PROCESS_ERROR_EXIT_CODE {
		t.Errorf("expected error exit code, got %s", res.ExitCode)
	}
}
