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

func DecryptionOracle(unknownBytes []byte, blockSize int) (plaintext []byte) {
	randomKey := GenerateRandomAESKey()

	var finalPlaintext []byte
	var asciiBytes = []byte(allAscii)

	// Construct map of blocks with last byte changed.
	m := make(map[string]byte)
	for _, asciiByte := range asciiBytes {
		var testInput []byte

		for i := 0; i < 15; i++ {
			testInput = append(testInput, 'A')
		}

		testInput = append(testInput, asciiByte)
		ciphertext := PadAndEncryptECBMode(testInput, randomKey)
		m[string(ciphertext)] = asciiByte
	}

	// Now step through all bytes in unknownBytes and decrypt them one at a time
	// using our map.
	bytesLeft := unknownBytes
	for j := 0; j < len(unknownBytes); j++ {
		var testInput []byte

		// Make plaintext one byte short of blockSize
		for i := 0; i < 15; i++ {
			testInput = append(testInput, 'A')
		}

		for _, b := range bytesLeft {
			testInput = append(testInput, b)
		}

		ciphertext := PadAndEncryptECBMode(testInput, randomKey)
		testBlock := string(ciphertext[:blockSize])
		finalPlaintext = append(finalPlaintext, m[testBlock])

		bytesLeft = bytesLeft[1:]
	}
	return finalPlaintext
}

func PickRandomAsciiCharacter() byte {
	rand.Seed(time.Now().Unix() + 1)
	randomInt := randomInt(0, len(allAscii))
	char := allAscii[randomInt]
	return char
}

func DecryptionOracleRandomPrefix(unknownBytes []byte, blockSize int) (plaintext []byte) {
	randomKey := GenerateRandomAESKey()

	var finalPlaintext []byte
	var asciiBytes = []byte(allAscii)

	// Generate a fixed, random length byte slice. We will prepend this to all
	// plaintexts.
	rand.Seed(time.Now().Unix() + 1)
	numBytesInPrefix := randomInt(1, 10)
	bytesBeforePlaintext := make([]byte, numBytesInPrefix)
	for k := 0; k < numBytesInPrefix; k++ {
		bytesBeforePlaintext[k] = PickRandomAsciiCharacter()
	}

	// Construct map of blocks with last byte changed.
	m := make(map[string]byte)
	for _, asciiByte := range asciiBytes {
		var testInput []byte

		// Add the random prefix
		for _, prefixByte := range bytesBeforePlaintext {
			testInput = append(testInput, prefixByte)
		}

		numberOfAsToAdd := blockSize - numBytesInPrefix - 1
		for i := 0; i < numberOfAsToAdd; i++ {
			testInput = append(testInput, 'A')
		}

		testInput = append(testInput, asciiByte)

		ciphertext := PadAndEncryptECBMode(testInput, randomKey)
		m[string(ciphertext)] = asciiByte
	}

	// Now step through all bytes in unknownBytes and decrypt them one at a time
	// using our map.
	bytesLeft := unknownBytes
	for j := 0; j < len(unknownBytes); j++ {
		var testInput []byte

		// Add the random prefix
		for _, prefixByte := range bytesBeforePlaintext {
			testInput = append(testInput, prefixByte)
		}

		// Make plaintext one byte short of blockSize
		numberOfAsToAdd := blockSize - numBytesInPrefix - 1
		for i := 0; i < numberOfAsToAdd; i++ {
			testInput = append(testInput, 'A')
		}

		for _, b := range bytesLeft {
			testInput = append(testInput, b)
		}

		ciphertext := PadAndEncryptECBMode(testInput, randomKey)
		testBlock := string(ciphertext[:blockSize])
		finalPlaintext = append(finalPlaintext, m[testBlock])

		bytesLeft = bytesLeft[1:]
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
