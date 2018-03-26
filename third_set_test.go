package gocryptopals_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/redshiftzero/gocryptopals"
)

func TestCBCPaddingOracle(t *testing.T) {
	content, err := ioutil.ReadFile("challengefiles/17.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	key := gocryptopals.GenerateRandomAESKey()
	selectedLine := gocryptopals.PickRandomLine(content)
	ciphertext := gocryptopals.CBCPaddingEncryptLine(selectedLine, key)

	validPadding := gocryptopals.CBCPaddingDecryptLine(ciphertext, key)

	fmt.Printf("%v", ciphertext)
	fmt.Printf("%v", validPadding)
}
