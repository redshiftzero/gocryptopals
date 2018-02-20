package gocryptopals

func PKCS7Pad(plaintext string, blockSize int) (ciphertext string) {
	plaintextBytes := []byte(plaintext)

	// No padding needed
	if len(plaintext)%blockSize == 0 {
		return string(plaintextBytes)
	}

	// Padding needed
	paddingBytes := blockSize - len(plaintext)%blockSize
	for i := 0; i < paddingBytes; i++ {
		plaintextBytes = append(plaintextBytes, byte(paddingBytes))
	}
	return string(plaintextBytes)
}
