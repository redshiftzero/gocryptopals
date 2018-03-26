package gocryptopals

import (
  "math/rand"
  "time"
  "strings"
)


func PickRandomLine(content []byte) (selectedLine []byte) {
    lines := strings.Split(string(content), "\n")
    rand.Seed(time.Now().Unix())
    index := RandomInt(0, len(lines) - 1)
    selectedLine = []byte(lines[index])
    return selectedLine
}

func CBCPaddingEncryptLine(content []byte, key []byte) (ciphertext []byte) {
    blockSize := 16
    paddedPlaintext := PKCS7Pad(string(content), blockSize)

    // construct IV
    var iv_e []byte
    for i := 0; i < blockSize; i++ {
      iv_e = append(iv_e, byte(0))
    }

    // Encrypt with CBC mode
    ciphertextStr := EncryptAESInCBCMode([]byte(paddedPlaintext), string(key), iv_e)
    ciphertext = []byte(ciphertextStr)
    return ciphertext
}

func CBCPaddingDecryptLine(ciphertext []byte, key []byte) (isPaddingValid bool) {
    blockSize := 16

    var iv_d []byte
    for i := 0; i < blockSize; i++ {
    	iv_d = append(iv_d, byte(0))
    }

    paddedPlaintext := DecryptAESInCBCMode(ciphertext, string(key), iv_d)

    _, err := PKCS7PadValidation(paddedPlaintext, blockSize)
    if err != nil {
      return false
    }
    return true
}
