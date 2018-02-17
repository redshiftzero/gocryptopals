package gocryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log"
	"strings"
)

func ConvertHexToBase64(hexString string) (base64String string) {
	// Convert hex to bytes
	bytes := ConvertHexToBytes(hexString)

	// Convert bytes to base64
	base64String = base64.StdEncoding.EncodeToString(bytes)
	return base64String
}

func ConvertHexToBytes(hexString string) (bytesValue []byte) {
	bytesValue, err := hex.DecodeString(hexString)
	if err != nil {
		log.Println("error converting hex to bytes: ", err)
	}
	return bytesValue
}

func ConvertBytesToHex(bytesValue []byte) (hexString string) {
	hexString = hex.EncodeToString(bytesValue)
	return hexString
}

func FixedXOR(firstHexString string, secondHexString string) (resultHex string) {
	// Convert each string to []byte
	firstBytes := ConvertHexToBytes(firstHexString)
	secondBytes := ConvertHexToBytes(secondHexString)

	// Bail if they are different lengths
	if len(firstBytes) != len(secondBytes) {
		log.Println("strings are not the same length")
		return
	}

	// Now XOR byte by byte and store result back in firstBytes
	for i, b := range secondBytes {
		firstBytes[i] ^= b
	}
	resultHex = ConvertBytesToHex(firstBytes)
	return resultHex
}

type BruteForceSearchPotentialSolution struct {
	plaintext string
	key       string
	metric    float64
}

func BreakSingleCharXOR(ciphertext string) (plaintext string, key string) {
	// Ciphertext is hex, first convert to bytes
	ciphertextBytes := ConvertHexToBytes(ciphertext)

	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	var potentialSolutions = [26]BruteForceSearchPotentialSolution{}

	for i, letter := range alphabet {
		var buffer bytes.Buffer
		var metric float64
		for _, b := range ciphertextBytes {
			char := b ^ byte(letter)
			buffer.WriteString(string(char))

			// If the resulting plaintext char is a very common en character,
			// then increment the metric.
			if strings.ContainsAny(string(char), "EeTtAaOoIiNn") {
				metric += 1
			}
		}

		// Store this result
		potentialSolutions[i] = BruteForceSearchPotentialSolution{
			plaintext: buffer.String(),
			key:       string(letter),
			metric:    metric,
		}
	}

	// Return the best solution
	bestMetric := 0.0
	bestSolution := 0
	for i, solution := range potentialSolutions {
		if solution.metric > bestMetric {
			bestMetric = solution.metric
			bestSolution = i
		}
	}

	plaintext = potentialSolutions[bestSolution].plaintext
	key = potentialSolutions[bestSolution].key
	return plaintext, key
}
