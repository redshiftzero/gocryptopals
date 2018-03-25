package gocryptopals_test

import (
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

func TestValidPKCS7Pad(t *testing.T) {
	blockSize := 16
	paddedPlaintext := "ICE ICE BABY\x04\x04\x04\x04"
	plaintext, err := gocryptopals.PKCS7PadValidation(paddedPlaintext, blockSize)
	if err != nil || plaintext != "ICE ICE BABY" {
		t.Fail()
	}
}

var pkcs7validationfailuretests = []struct {
	plaintext string
}{
	{"ICE ICE BABY\x05\x05\x05\x05"},
	{"ICE ICE BABY\x01\x02\x03\x04"},
	{"ICE ICE BABY"},
}

func TestInvalidPKCS7Pad(t *testing.T) {
	blockSize := 16
	for _, tt := range pkcs7validationfailuretests {
		s, err := gocryptopals.PKCS7PadValidation(tt.plaintext, blockSize)
		if err == nil {
			t.Errorf("PKCS7PadValidation(%q, %q) => %q, want error", tt.plaintext, blockSize, s)
		}
	}
}
