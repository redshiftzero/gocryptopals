package gocryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func ConvertHexToBase64(hexString string) (base64String string) {
	// Convert hex to bytes
	bytes, err := hex.DecodeString(hexString)
	if err != nil {
		log.Println("error converting hex to bytes: ", err)
	}

	// Convert bytes to base64
	base64String = base64.StdEncoding.EncodeToString(bytes)
	return base64String
}
