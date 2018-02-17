package gocryptopals_test

import (
	"fmt"

	"github.com/redshiftzero/gocryptopals"
)

func ExampleHexToBase64() {
	testHexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Println(gocryptopals.ConvertHexToBase64(testHexString))
	// Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}
