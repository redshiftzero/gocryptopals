package gocryptopals

import (
	"fmt"
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

func DecryptionOracle(unknownBytes []byte) (plaintext []byte) {
	randomKey := GenerateRandomAESKey()

	var finalPlaintext []byte
	var blockSize = 16
	var asciiBytes = []byte(allAscii)

	// For each byte in unknownBytes, we will need to construct a mapping
	// of every possible byte.
	//m := make(map[string]int)

	var testInput []byte
	AasciiBytes := make([]byte, blockSize-1)

	// Append the plaintext.
	for _, b := range AasciiBytes {
		fmt.Printf(string(b))
		testInput = append(testInput, 'A')
	}

	for _, b := range unknownBytes {
		testInput = append(testInput, b)
	}

	ciphertext := PadAndEncryptECBMode(testInput, randomKey)
	ciphertextStr := string(ciphertext)

	fmt.Printf("One byte short: %v\n", ciphertextStr)

	for _, asciiByte := range asciiBytes {
		var testInput []byte
		AasciiBytes := make([]byte, blockSize-1)

		// Append the plaintext.
		for _, b := range AasciiBytes {
			fmt.Printf(string(b))
			testInput = append(testInput, 'A')
		}

		testInput = append(testInput, asciiByte)

		for _, b := range unknownBytes {
			testInput = append(testInput, b)
		}

		ciphertext := PadAndEncryptECBMode(testInput, randomKey)
		ciphertextStr := string(ciphertext)
		fmt.Printf("%q: %v\n", asciiByte, ciphertextStr)
	}

	return finalPlaintext
}

func GetBlockSize() (blockSize int) {
	// Here we manually compute the blocksize by encrypting a single character
	// and observing the ciphertext length.

	var ciphertext []byte
	var plaintext []byte

	randomKey := GenerateRandomAESKey()
	plaintext = append(plaintext, 'A')
	ciphertext = PadAndEncryptECBMode(plaintext, randomKey)
	blockSize = len(ciphertext)
	return blockSize
}

func PadAndEncryptECBMode(plaintext []byte, key []byte) (ciphertext []byte) {
	blockSize := 16
	plaintextStr := PKCS7Pad(string(plaintext), blockSize)

	// Encrypt with ECB mode
	ciphertextStr := EncryptAESInECBMode([]byte(plaintextStr), string(key))
	ciphertext = []byte(ciphertextStr)
	return ciphertext
}
