package gocryptopals

import (
  "crypto/aes"
  "fmt"
  "bytes"
)

func DecryptAESInECBMode(ciphertextBytes []byte, key string) (plaintext string) {
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("could not create cipher %v: ", err)
	}

	if len(ciphertextBytes) < aes.BlockSize {
		panic("ciphertext too short")
	}

	if len(ciphertextBytes)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	var plaintextBytes []byte
	singleBlockPlaintextBytes := make([]byte, aes.BlockSize)
	for len(ciphertextBytes) > 0 {
		block.Decrypt(singleBlockPlaintextBytes, ciphertextBytes)
		for _, b := range singleBlockPlaintextBytes {
			plaintextBytes = append(plaintextBytes, b)
		}
		ciphertextBytes = ciphertextBytes[aes.BlockSize:]
	}

	plaintext = string(plaintextBytes)
	return plaintext
}

func DetectAESInECBMode(ciphertextBytes []byte) (isECB bool) {
	numRepeatedBlocks := 0
	blockSize := 16
	numChunks := len(ciphertextBytes) / blockSize

	for i := 1; i < numChunks; i++ {
		for j := 1; j < numChunks; j++ {
			if bytes.Equal(ciphertextBytes[(i-1)*blockSize:i*blockSize], ciphertextBytes[(j-1)*blockSize:j*blockSize]) && i != j {
				numRepeatedBlocks++
			}
		}
	}

	if numRepeatedBlocks == 0 {
		return false
	}
	return true
}
