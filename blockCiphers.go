package gocryptopals

import (
	"crypto/aes"
  "crypto/cipher"

	"bytes"
	"fmt"
)

func SetupAESInECBMode(input []byte, key string) cipher.Block {
	keyBytes := []byte(key)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("could not create cipher %v: ", err)
	}

	if len(input) < aes.BlockSize {
		panic("input too short, you need to pad it")
	}

	if len(input)%aes.BlockSize != 0 {
		panic("input is not a multiple of the block size, you need to pad it")
	}
	return block
}

func DecryptAESInECBMode(ciphertextBytes []byte, key string) (plaintext string) {
	var plaintextBytes []byte

	block := SetupAESInECBMode(ciphertextBytes, key)
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

func EncryptAESInECBMode(plaintextBytes []byte, key string) (ciphertext string) {
	var ciphertextBytes []byte

	block := SetupAESInECBMode(plaintextBytes, key)
	singleBlockCiphertextBytes := make([]byte, aes.BlockSize)

	for len(plaintextBytes) > 0 {
		block.Encrypt(singleBlockCiphertextBytes, plaintextBytes)

		for _, b := range singleBlockCiphertextBytes {
			ciphertextBytes = append(ciphertextBytes, b)
		}
		plaintextBytes = plaintextBytes[aes.BlockSize:]
	}

	ciphertext = string(ciphertextBytes)
	return ciphertext
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
