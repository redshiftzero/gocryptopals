package gocryptopals

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func ParseStructuredCookie(input string) (cookieJSON []byte, err error) {
	splittedInputs := strings.Split(input, "&")

	// Construct map of k=v pairs.
	cookieMap := make(map[string]string)
	for _, input := range splittedInputs {
		keyValuePair := strings.Split(input, "=")
		cookieMap[keyValuePair[0]] = keyValuePair[1]
	}

	// Now encode this map as JSON.
	cookieJSON, err = json.Marshal(cookieMap)
	if err != nil {
		fmt.Printf("err: %v", err)
		return nil, err
	}
	return cookieJSON, nil
}

func ProfileFor(email string) (cookieInput string, cookieJSON []byte, err error) {
	// Return an error if an invalid character is used.
	invalidChars := [2]string{"=", "&"}
	for _, invalidChar := range invalidChars {
		if strings.Contains(email, invalidChar) {
			err := errors.New("email cannot contain = or &")
			return "", nil, err
		}
	}

	cookieInput = "email=" + email + "&uid=10&role=user"
	cookieJSON, err = ParseStructuredCookie(cookieInput)
	if err != nil {
		fmt.Printf("err: %v", err)
		return "", nil, err
	}
	return cookieInput, cookieJSON, nil
}
