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
