package gocryptopals_test

import (
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/redshiftzero/gocryptopals"
)

var pkcs7paddingtests = []struct {
	plaintext string
	blocksize int
	out       string
}{
	{"YELLOW SUBMARINE", 16, "YELLOW SUBMARINE"},
	{"YELLOW SUBMARINE", 10, "YELLOW SUBMARINE\x04\x04\x04\x04"},
	{"YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04"},
}

func TestPKCS7Pad(t *testing.T) {
	for _, tt := range pkcs7paddingtests {
		s := gocryptopals.PKCS7Pad(tt.plaintext, tt.blocksize)
		if s != tt.out {
			t.Errorf("PKCS7Pad(%q, %q) => %q, want %q", tt.plaintext, tt.blocksize, s, tt.out)
		}
	}
}

func TestAESInCBCMode(t *testing.T) {
	content, err := ioutil.ReadFile("challengefiles/10.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	ciphertextBase64 := string(content)
	ciphertextAscii := gocryptopals.ConvertBase64ToAscii(ciphertextBase64)
	key := "YELLOW SUBMARINE"

	// construct IV
	blockSize := 16
	var iv []byte
	for i := 0; i < blockSize; i++ {
		iv = append(iv, byte(0))
	}

	plaintext := gocryptopals.DecryptAESInCBCMode(ciphertextAscii, key, iv)

	if !strings.Contains(plaintext, "Play that funky music, white boy") {
		t.Fail()
	}
}

func TestECBandCBCEncryptionOracle(t *testing.T) {
	input, err := ioutil.ReadFile("texts/returnofthekingch1.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	ciphertext, isECBtruth := gocryptopals.EncryptionOracle(input)

	isECBobserved := gocryptopals.DetectAESInECBMode(ciphertext)

	if isECBtruth != isECBobserved {
		t.Fail()
	}
}

func TestByteByByteECBDecryption(t *testing.T) {
	unknownString, err := ioutil.ReadFile("challengefiles/12.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	// 1. Discover the block size of the cipher.
	blockSize := gocryptopals.GetBlockSize()
	if blockSize != 16 {
		t.Fail()
	}

	// 2. Detect that the function is using ECB.
	input, err := ioutil.ReadFile("texts/returnofthekingch1.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	randomKey := gocryptopals.GenerateRandomAESKey()
	ciphertext := gocryptopals.PadAndEncryptECBMode(input, randomKey)
	isECBobserved := gocryptopals.DetectAESInECBMode(ciphertext)

	if isECBobserved == false {
		t.Fail()
	}

	// 3. Craft input one block short, build dict of possible values.
	plaintext := gocryptopals.DecryptionOracle([]byte(unknownString), blockSize)

	if string(plaintext) != string(unknownString) {
		t.Fail()
	}
}
