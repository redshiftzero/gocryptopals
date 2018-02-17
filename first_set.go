package gocryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func ConvertHexToBase64(hexString string) (base64String string) {
	// Convert hex to bytes
	bytes := ConvertHexToBytes(hexString)

	// Convert bytes to base64
	base64String = base64.StdEncoding.EncodeToString(bytes)
	return base64String
}

func ConvertHexToBytes(hexString string) (bytesValue []byte) {
	bytesValue, err := hex.DecodeString(hexString)
	if err != nil {
		log.Println("error converting hex to bytes: ", err)
	}
	return bytesValue
}

func ConvertBytesToHex(bytesValue []byte) (hexString string) {
	hexString = hex.EncodeToString(bytesValue)
	return hexString
}

func FixedXOR(firstHexString string, secondHexString string) (resultHex string) {
	// Convert each string to []byte
	firstBytes := ConvertHexToBytes(firstHexString)
	secondBytes := ConvertHexToBytes(secondHexString)

	// Bail if they are different lengths
	if len(firstBytes) != len(secondBytes) {
		log.Println("strings are not the same length")
		return
	}

	// Now XOR byte by byte and store result back in firstBytes
	for i, b := range secondBytes {
		firstBytes[i] ^= b
	}
	resultHex = ConvertBytesToHex(firstBytes)
	return resultHex
}
