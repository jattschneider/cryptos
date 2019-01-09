package cryptos

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestShouldGenerateKey32GivenPassword(t *testing.T) {
	key, err := Key32([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key32")
	}
	if len(key) != 32 {
		t.Error("Incorrect key len")
	}
	fmt.Printf("key32: %v\n", base64.StdEncoding.EncodeToString(key))
}

func TestShouldGenerateKey16GivenPassword(t *testing.T) {
	key, err := Key16([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key16")
	}
	if len(key) != 16 {
		t.Error("Incorrect key len")
	}
	fmt.Printf("key16: %v\n", base64.StdEncoding.EncodeToString(key))
}

func TestShouldGenerateNonce(t *testing.T) {
	nonce, err := Nonce()
	if err != nil {
		t.Error("Cannot generate a nonce")
	}
	fmt.Printf("nonce: %v\n", base64.StdEncoding.EncodeToString(nonce))
}

func TestShouldBeAnEncryptString(t *testing.T) {
	es := "ENC(cLqUafMcfzJOt3FyOLmIAqwVJJAoXj3o3h3cZrM4EIo=)"
	if !IsEncryptedString(es) {
		t.Error("Should be an encrypted string")
	}

	es = "ENC(lalala)"
	if !IsEncryptedString(es) {
		t.Error("Should be an encrypted string")
	}
}

func TestShouldExtractInnerEncryptedString(t *testing.T) {
	es := "ENC(cLqUafMcfzJOt3FyOLmIAqwVJJAoXj3o3h3cZrM4EIo=)"
	if InnerEncryptedString(es) != "cLqUafMcfzJOt3FyOLmIAqwVJJAoXj3o3h3cZrM4EIo=" {
		t.Error("Should extract the inner encrypted string")
	}

	es = "ENC(lalala)"
	if InnerEncryptedString(es) != "lalala" {
		t.Error("Should extract the inner encrypted string")
	}
}

func TestShouldGCMEncryptAndGCMDecryptGivenKey32(t *testing.T) {
	key, err := Key32([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := Nonce()
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	msg := "Hello Encrypter!"

	enc, err := GCMEncrypt(key, nonce, []byte(msg))
	if err != nil {
		t.Error("Cannot GCMEncrypt")
	}
	dec, err := GCMDecrypt(key, nonce, enc)
	if err != nil {
		t.Error("Cannot GCMDecrypt")
	}

	if string(dec) != msg {
		t.Errorf("Expected %v got %v", msg, dec)
	}
}

func TestShouldGCMEncryptAndGCMDecryptGivenKey16(t *testing.T) {
	key, err := Key16([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := Nonce()
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	msg := "Hello Encrypter!"

	enc, err := GCMEncrypt(key, nonce, []byte(msg))
	if err != nil {
		t.Error("Cannot GCMEncrypt")
	}
	dec, err := GCMDecrypt(key, nonce, enc)
	if err != nil {
		t.Error("Cannot GCMDecrypt")
	}

	if string(dec) != msg {
		t.Errorf("Expected %v got %v", msg, dec)
	}
}

func TestShouldEncryptAndDecryptGivenKey32(t *testing.T) {
	key, err := Key32([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := Nonce()
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	msg := "Hello Encrypter!"

	es, err := EncryptString(key, nonce, msg)
	if err != nil {
		t.Error("Cannot EncryptString")
	}
	ds, err := DecryptString(key, nonce, es)
	if err != nil {
		t.Error("Cannot DecryptString")
	}

	if string(ds) != msg {
		t.Errorf("Expected %v got %v", msg, ds)
	}
}

func TestShouldEncryptAndDecryptGivenKey16(t *testing.T) {
	key, err := Key16([]byte("Swordfish"))
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := Nonce()
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	msg := "Hello Encrypter!"

	es, err := EncryptString(key, nonce, msg)
	if err != nil {
		t.Error("Cannot EncryptString")
	}
	ds, err := DecryptString(key, nonce, es)
	if err != nil {
		t.Error("Cannot DecryptString")
	}

	if string(ds) != msg {
		t.Errorf("Expected %v got %v", msg, ds)
	}
}

func TestShouldEncrypt(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString("lJVRh3lGtxZwlwplx+Wz9XbJSEouhfcPKmYbBM45ODE=")
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := base64.StdEncoding.DecodeString("hoOLlooQPN21ufCy")
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	ees := "ENC(btv/Y76zX88PV1CJUzxSkutBIJA4nmhUzPjC8tC+pQg=)"
	msg := "Hello Encrypter!"
	es, err := EncryptString(key, nonce, msg)
	if err != nil {
		t.Error("Cannot EncryptString")
	}

	if es != ees {
		t.Errorf("Expected %v got %v", ees, string(es))
	}
}

func TestShouldDecrypt(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString("lJVRh3lGtxZwlwplx+Wz9XbJSEouhfcPKmYbBM45ODE=")
	if err != nil {
		t.Error("Cannot generate a key")
	}
	nonce, err := base64.StdEncoding.DecodeString("hoOLlooQPN21ufCy")
	if err != nil {
		t.Error("Cannot generate a nonce")
	}

	eds := "Hello Encrypter!"
	es := "ENC(btv/Y76zX88PV1CJUzxSkutBIJA4nmhUzPjC8tC+pQg=)"
	ds, err := DecryptString(key, nonce, es)
	if err != nil {
		t.Error("Cannot DecryptString")
	}

	if ds != eds {
		t.Errorf("Expected %v got %v", eds, ds)
	}
}
