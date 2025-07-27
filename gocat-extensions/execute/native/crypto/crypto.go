package crypto

import (
	"encoding/base64"

	gocrypto "github.com/mitre/gocat/crypto"
	"github.com/mitre/gocat/execute/native/util"
)

const argErrMsg = "Expected format: [base64 key] [base64 data]"

func init() {
	util.NativeMethods["Encrypt"] = EncryptData
	util.NativeMethods["Decrypt"] = DecryptData
}

// EncryptData encrypts base64 encoded plaintext using the provided base64 key.
// Returns base64 encoded ciphertext.
func EncryptData(args []string) util.NativeCmdResult {
	if len(args) != 2 {
		return util.GenerateErrorResultFromString(argErrMsg, util.INPUT_ERROR_EXIT_CODE)
	}
	key, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		return util.GenerateErrorResult(err, util.INPUT_ERROR_EXIT_CODE)
	}
	data, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return util.GenerateErrorResult(err, util.INPUT_ERROR_EXIT_CODE)
	}
	cipherText, err := gocrypto.EncryptAES(key, data)
	if err != nil {
		return util.GenerateErrorResult(err, util.PROCESS_ERROR_EXIT_CODE)
	}
	encoded := base64.StdEncoding.EncodeToString(cipherText)
	return util.NativeCmdResult{Stdout: []byte(encoded), ExitCode: util.SUCCESS_EXIT_CODE}
}

// DecryptData decrypts base64 encoded ciphertext using the provided base64 key.
// Returns base64 encoded plaintext.
func DecryptData(args []string) util.NativeCmdResult {
	if len(args) != 2 {
		return util.GenerateErrorResultFromString(argErrMsg, util.INPUT_ERROR_EXIT_CODE)
	}
	key, err := base64.StdEncoding.DecodeString(args[0])
	if err != nil {
		return util.GenerateErrorResult(err, util.INPUT_ERROR_EXIT_CODE)
	}
	data, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return util.GenerateErrorResult(err, util.INPUT_ERROR_EXIT_CODE)
	}
	plainText, err := gocrypto.DecryptAES(key, data)
	if err != nil {
		return util.GenerateErrorResult(err, util.PROCESS_ERROR_EXIT_CODE)
	}
	encoded := base64.StdEncoding.EncodeToString(plainText)
	return util.NativeCmdResult{Stdout: []byte(encoded), ExitCode: util.SUCCESS_EXIT_CODE}
}
