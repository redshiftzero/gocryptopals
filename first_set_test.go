package gocryptopals_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/redshiftzero/gocryptopals"
)

func ExampleHexToBase64() {
	testHexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Println(gocryptopals.ConvertHexToBase64(testHexString))
	// Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}

func ExampleFixedXOR() {
	firstHexString := "1c0111001f010100061a024b53535009181c"
	secondHexString := "686974207468652062756c6c277320657965"
	hexResultString := gocryptopals.FixedXOR(firstHexString, secondHexString)
	asciiResultString := gocryptopals.ConvertHexToBytes(hexResultString)
	fmt.Printf("%s (=%s)", asciiResultString, hexResultString)
	// Output: the kid don't play (=746865206b696420646f6e277420706c6179)
}

func ExampleBreakSingleCharXOR() {
	ciphertext := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	plaintext, key, _ := gocryptopals.BreakSingleCharXOR(ciphertext)
	fmt.Printf("%s - Key: %s ", plaintext, key)
	// Output: Cooking MC's like a pound of bacon - Key: X
}

func ExampleDetectSingleCharXOR() {
	content, err := ioutil.ReadFile("challengefiles/4.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	lines := strings.Split(string(content), "\n")
	plaintext, _, _ := gocryptopals.DetectSingleCharXOR(lines)
	fmt.Printf("%v", plaintext)
	// Output: Now that the party is jumping
}

func ExampleRepeatingKeyXOR() {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	ciphertext := gocryptopals.RepeatingKeyXOR(plaintext, "ICE")
	fmt.Printf(ciphertext)
	// Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
}

func ExampleEditDistance() {
	firstStringBytes := []byte("this is a test")
	secondStringBytes := []byte("wokka wokka!!!")
	editDistance := gocryptopals.ComputeEditDistance(firstStringBytes, secondStringBytes)
	fmt.Printf("%v", editDistance)
	// Output: 37
}

func ExampleBreakRepeatingKeyXOR() {
	content, err := ioutil.ReadFile("challengefiles/6.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}
	ciphertextBase64 := string(content)
	ciphertextAscii := gocryptopals.ConvertBase64ToAscii(ciphertextBase64)

	key := gocryptopals.BreakRepeatingKeyXOR(ciphertextAscii)
	fmt.Printf("%v", key)
	// Output: Terminator X: Bring the noise
}

func TestDecryptAESInECBMode(t *testing.T) {
	content, err := ioutil.ReadFile("challengefiles/7.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}

	ciphertextBase64 := string(content)
	ciphertextAscii := gocryptopals.ConvertBase64ToAscii(ciphertextBase64)
	key := "YELLOW SUBMARINE"
	plaintext := gocryptopals.DecryptAESInECBMode(ciphertextAscii, key)

	if !strings.Contains(plaintext, "I'm back and I'm ringin' the bell") {
		t.Fail()
	}
}

func ExampleDetectAESInECBMode() {
	content, err := ioutil.ReadFile("challengefiles/8.txt")
	if err != nil {
		log.Println("error loading file: ", err)
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		ciphertextAscii := gocryptopals.ConvertBase64ToAscii(line)
		isECB := gocryptopals.DetectAESInECBMode(ciphertextAscii)
		if isECB {
			fmt.Printf("%v", line)
		}
	}
	// Output: d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
}
