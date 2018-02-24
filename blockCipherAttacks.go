package gocryptopals

import (
	"math/rand"
	"time"
)

func randomInt(min, max int) int {
	return rand.Intn(max-min) + min
}

// This is an ECB/CBC oracle for challenge 11.
func EncryptionOracle(input []byte) (ciphertext []byte, isECB bool) {
	key := GenerateRandomAESKey()
	isECB = GenerateRandomBool()

	var plaintext []byte

	// "append 5-10 bytes (count chosen randomly) before the plaintext"
	rand.Seed(time.Now().Unix())
	numBytesBeforePlaintext := randomInt(5, 10)
	bytesBeforePlaintext := make([]byte, numBytesBeforePlaintext)

	for _, b := range bytesBeforePlaintext {
		plaintext = append(plaintext, b)
	}

	// Append the plaintext.
	for _, b := range input {
		plaintext = append(plaintext, b)
	}

	// "append 5-10 bytes after the plaintext."
	rand.Seed(time.Now().Unix() + 1)
	numBytesAfterPlaintext := randomInt(5, 10)
	bytesafterPlaintext := make([]byte, numBytesAfterPlaintext)

	for _, b := range bytesafterPlaintext {
		plaintext = append(plaintext, b)
	}

	plaintextStr := PKCS7Pad(string(plaintext), 16)
	plaintext = []byte(plaintextStr)

	var ciphertextStr string
	if isECB == true {
		// Encrypt with ECB mode
		ciphertextStr = EncryptAESInECBMode(plaintext, string(key))
	} else {
		// Encrypt with CBC mode
		iv := GenerateRandomAESKey()
		ciphertextStr = EncryptAESInCBCMode(plaintext, string(key), iv)
	}

	ciphertext = []byte(ciphertextStr)
	return ciphertext, isECB
}
