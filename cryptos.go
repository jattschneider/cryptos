package cryptos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const encryptedStringPrefix = "ENC("
const encryptedStringSuffix = ")"

func salt() ([]byte, error) {
	return randomBytes(8)
}

// Nonce never use more than 2^32 random nonces with a given key because of the risk of a repeat.
func Nonce() ([]byte, error) {
	return randomBytes(12)
}

func randomBytes(len int) ([]byte, error) {
	bytes := make([]byte, len)
	n, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, errors.New("Invalid len")
	}
	return bytes, nil
}

// Key32 generates AES-256 32 bytes key
func Key32(password []byte) ([]byte, error) {
	return key(password, 32)
}

// Key16 generates AES-128 16 bytes key
func Key16(password []byte) ([]byte, error) {
	return key(password, 16)
}

func key(password []byte, keyLen int) ([]byte, error) {
	salt, err := salt()
	if err != nil {
		return nil, err
	}
	return scrypt.Key(password, salt, 16384, 8, 1, keyLen)
}

// EncryptString encrypts a string s.
func EncryptString(key, nonce []byte, s string) (string, error) {
	ciphertext, err := GCMEncrypt(key, nonce, []byte(s))
	if err != nil {
		return "", err
	}
	return Base64EncodeEncryptedString(ciphertext), nil
}

// GCMEncrypt the key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func GCMEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptString decrypts a string s
func DecryptString(key, nonce []byte, s string) (string, error) {
	ciphertext, err := Base64DecodeInnerEncryptedString(s)
	if err != nil {
		return "", err
	}

	plaintext, err := GCMDecrypt(key, nonce, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// GCMDecrypt the key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func GCMDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// Base64Encode returns the base64 encoding of src.
func Base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// Base64Decode returns the bytes represented by the base64 string s.
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// IsEncryptedString a string is considered "encrypted" when it appears surrounded by ENC(...).
func IsEncryptedString(s string) bool {
	if len(s) == 0 || s == "" {
		return false
	}
	trimmed := strings.TrimSpace(s)
	return strings.HasPrefix(trimmed, encryptedStringPrefix) && strings.HasSuffix(trimmed, encryptedStringSuffix)
}

// InnerEncryptedString returns the inner "encrypted string" surrounded by ENC(...).
func InnerEncryptedString(s string) string {
	return s[len(encryptedStringPrefix) : len(s)-len(encryptedStringSuffix)]
}

// Base64DecodeInnerEncryptedString returns the bytes represented by the base64 inner "encrypted string" surrounded by ENC(...).
func Base64DecodeInnerEncryptedString(s string) ([]byte, error) {
	return Base64Decode(InnerEncryptedString(s))
}

// Base64EncodeEncryptedString returns the base64 encoding of "encrypted string" surrounded by ENC(...).
func Base64EncodeEncryptedString(src []byte) string {
	s := Base64Encode(src)
	return fmt.Sprintf("%v%v%v", encryptedStringPrefix, s, encryptedStringSuffix)
}
