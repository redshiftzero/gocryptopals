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

func TestForProfileInvalidCharacters(t *testing.T) {
	email := "jenjenjennnn@invalid&email=input"
	_, err := gocryptopals.ProfileFor(email)
	if err == nil {
		t.Fail()
	}
}

func ExampleValidProfileFor() {
	email := "foo@bar.com"
	cookieJSON, _ := gocryptopals.ProfileFor(email)
	fmt.Printf("%v", string(cookieJSON))
	// Output: {"email":"foo@bar.com","role":"user","uid":"10"}
}
