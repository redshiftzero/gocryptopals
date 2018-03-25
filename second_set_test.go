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

func TestByteByByteECBDecryptionRandomPrefix(t *testing.T) {
	unknownString, err := ioutil.ReadFile("challengefiles/12.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	blockSize := gocryptopals.GetBlockSize()
	plaintext := gocryptopals.DecryptionOracleRandomPrefix([]byte(unknownString), blockSize)

	if string(plaintext) != string(unknownString) {
		t.Fail()
	}
}

func TestECBCutAndPaste(t *testing.T) {
	randomKey := gocryptopals.GenerateRandomAESKey()
	blockSize := 16

	// Encrypt the encoded user profile under the key
	// "provide" that to the "attacker".
	cookieInput, _, _ := gocryptopals.ProfileFor("foo@bar.com")
	ciphertext := gocryptopals.PadAndEncryptECBMode([]byte(cookieInput), randomKey)

	// Decrypt the encoded user profile and parse it.
	plaintext := gocryptopals.DecryptAESInECBMode([]byte(ciphertext), string(randomKey))

	// Now, using only ProfileFor, we need to generate a valid ciphertext
	// with role=admin. We can do this by paying attention to the block boundaries:
	// email=foo@bar.co | m&uid=10&role=us | er

	// Let's construct a ciphertext that has just admin and a bunch of trailing
	// whitespace by passing an email that will have the block boundaries as follows:
	// email=fooooooooo | admin            |

	inputWithAdmin, _, _ := gocryptopals.ProfileFor("foooooooooadmin           ")
	ciphertextWithAdmin := gocryptopals.PadAndEncryptECBMode([]byte(inputWithAdmin), randomKey)
	// From this ciphertext, let's take just the (second) block that has the string "admin".
	blockJustAdmin := ciphertextWithAdmin[blockSize : blockSize*2]

	// Now let's construct a ciphertext that has "role=" at the very end of a block:
	// email=fooba@bar. | com&uid=10&role=

	inputBlockAligned, _, _ := gocryptopals.ProfileFor("fooba@bar.com")
	ciphertextBlockAligned := gocryptopals.PadAndEncryptECBMode([]byte(inputBlockAligned), randomKey)
	// From this ciphertext, let's take just the plaintext up to "role="
	// so that we can paste our valid "admin   " block on the end.
	blocksEndingInRole := ciphertextBlockAligned[0 : blockSize*2]

	// Now add the block that just contains "admin" and some whitespace padding
	// to the block-aligned ciphertext.
	for _, b := range blockJustAdmin {
		blocksEndingInRole = append(blocksEndingInRole, b)
	}

	// Now let's decrypt - this should be a valid ciphertext with role=admin.
	plaintext = gocryptopals.DecryptAESInECBMode([]byte(blocksEndingInRole), string(randomKey))

	if !strings.Contains(plaintext, "role=admin") || strings.Contains(plaintext, "role=user") {
		t.Fail()
	}
}
