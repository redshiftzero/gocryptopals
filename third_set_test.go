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

	fmt.Printf("%v", gocryptopals.PickRandomLine(content))
}
