package gocryptopals_test

import (
	"fmt"
	"testing"

	"github.com/redshiftzero/gocryptopals"
)

func ExampleParseStructuredCookie() {
	input := "foo=bar&baz=qux&zap=zazzle"
	cookieJSON, _ := gocryptopals.ParseStructuredCookie(input)
	fmt.Printf("%v", string(cookieJSON))
	// Output: {"baz":"qux","foo":"bar","zap":"zazzle"}
}

func TestProfileForInvalidCharacters(t *testing.T) {
	email := "jenjenjennnn@invalid&email=input"
	_, _, err := gocryptopals.ProfileFor(email)
	if err == nil {
		t.Fail()
	}
}

func ExampleValidProfileFor() {
	email := "foo@bar.com"
	cookieInput, cookieJSON, _ := gocryptopals.ProfileFor(email)
	fmt.Printf("%v: %v", string(cookieInput), string(cookieJSON))
	// Output: email=foo@bar.com&uid=10&role=user: {"email":"foo@bar.com","role":"user","uid":"10"}
}
