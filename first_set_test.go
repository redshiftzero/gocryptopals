package gocryptopals_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

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
		log.Println("error loading files: ", err)
	}

	lines := strings.Split(string(content), "\n")
	plaintext, _, _ := gocryptopals.DetectSingleCharXOR(lines)
	fmt.Printf("%v", plaintext)
	// Output: Now that the party is jumping
}
