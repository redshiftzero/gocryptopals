package gocryptopals

import (
	"errors"
)

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

func PKCS7PadValidation(paddedPlaintext string, blockSize int) (plaintext string, err error) {
	plaintextBytes := []byte(paddedPlaintext)

	// No padding
	if len(plaintextBytes)%blockSize != 0 {
		err := errors.New("not padded to blocksize")
		return "", err
	}

	paddingBytes := make([]byte, 0)
	var validPaddingBytes int
	for i := blockSize - 1; i >= 0; i-- {
		paddingBytes = append(paddingBytes, plaintextBytes[i])

		// If these bytes were all padding, would it be valid?
		for _, paddingByte := range paddingBytes {
			if int(paddingByte) == len(paddingBytes) {
				validPaddingBytes++
			}
		}
	}

	finalPaddingBytes := paddingBytes[:validPaddingBytes]
	// Now let's check validity using the final value of validPaddingBytes
	for _, b := range finalPaddingBytes {
		if len(finalPaddingBytes) != int(b) {
			err = errors.New("invalid padding")
			return "", err
		}
	}

	return string(plaintextBytes[:blockSize-validPaddingBytes]), nil
}
