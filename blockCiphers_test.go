package gocryptopals_test

import (
	"testing"

	"github.com/redshiftzero/gocryptopals"
)

func TestAESEncryptionAndDecryptionInECBMode(t *testing.T) {
	key := "YELLOW SUBMARINE"
	testPlaintext := "PURPLE SUBMARINE"
	ciphertextAscii := gocryptopals.EncryptAESInECBMode([]byte(testPlaintext), key)
	plaintext := gocryptopals.DecryptAESInECBMode([]byte(ciphertextAscii), key)
	if plaintext != testPlaintext {
		t.Errorf("AES in ECB mode not consistent: %v != %v", testPlaintext, plaintext)
	}
}

func TestAESEncryptionAndDecryptionInCBCMode(t *testing.T) {
	key := "YELLOW SUBMARINE"
	testPlaintext := "PURPLE SUBMARINE"

	// construct IV
	blockSize := 16
	var iv_e []byte
	for i := 0; i < blockSize; i++ {
		iv_e = append(iv_e, byte(0))
	}

	ciphertextAscii := gocryptopals.EncryptAESInCBCMode([]byte(testPlaintext), key, iv_e)

	var iv_d []byte
	for i := 0; i < blockSize; i++ {
		iv_d = append(iv_d, byte(0))
	}

	plaintext := gocryptopals.DecryptAESInCBCMode([]byte(ciphertextAscii), key, iv_d)

	if plaintext != testPlaintext {
		t.Errorf("AES in CBC mode not consistent: %v != %v", testPlaintext, plaintext)
	}
}
