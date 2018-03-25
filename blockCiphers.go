package gocryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"bytes"
	"fmt"
)

func GenerateRandomAESKey() (key []byte) {
	blockSize := 16
	key = make([]byte, blockSize)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	return key
}

func GenerateRandomBool() bool {
	bytesRand := make([]byte, 1)
	_, err := rand.Read(bytesRand)
	if err != nil {
		fmt.Println("error:", err)
	}
	if bytesRand[0]&1 == 1 {
		return true
	}
	return false
}

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

// Decrypt a ciphertext given a key and IV using AES in Cipher-Block Chaining (CBC) mode.
func DecryptAESInCBCMode(ciphertextBytes []byte, key string, iv []byte) (plaintext string) {
	var plaintextBytes []byte

	block := SetupAESInECBMode(ciphertextBytes, key)

	blockCipherOutput := make([]byte, aes.BlockSize)

	for len(ciphertextBytes) > 0 {
		block.Decrypt(blockCipherOutput, ciphertextBytes)

		plaintextBlock := FixedXOR(iv, blockCipherOutput)

		for _, b := range plaintextBlock {
			plaintextBytes = append(plaintextBytes, b)
		}

		iv = ciphertextBytes[:aes.BlockSize]
		ciphertextBytes = ciphertextBytes[aes.BlockSize:]
	}

	plaintext = string(plaintextBytes)
	return plaintext
}

// Encrypt a ciphertext given a key and IV using AES in Cipher-Block Chaining (CBC) mode.
func EncryptAESInCBCMode(plaintextBytes []byte, key string, iv []byte) (ciphertext string) {
	var ciphertextBytes []byte

	block := SetupAESInECBMode(plaintextBytes, key)

	ciphertextBlock := make([]byte, aes.BlockSize)

	for len(plaintextBytes) > 0 {
		plaintextBlock := plaintextBytes[:aes.BlockSize]
		blockCipherInput := FixedXOR(iv, plaintextBlock)

		block.Encrypt(ciphertextBlock, blockCipherInput)

		for _, b := range ciphertextBlock {
			ciphertextBytes = append(ciphertextBytes, b)
		}

		iv = ciphertextBlock
		plaintextBytes = plaintextBytes[aes.BlockSize:]
	}

	ciphertext = string(ciphertextBytes)
	return ciphertext
}

// Decrypt a ciphertext given a key and IV using AES in ECB mode.
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

// Encrypt a ciphertext given a key using AES in ECB mode.
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

// Detect if a ciphertext was encrypted using ECB mode by looking for
// repeated ciphertext blocks.
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
