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
