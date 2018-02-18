package gocryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"strings"
)

const (
	alphabetLower         = "abcdefghijklmnopqrstuvwxyz"
	alphabetUpperAndLower = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	// https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
	englishFrequencies = [26]float64{
		8.12,  // a
		1.49,  // b
		2.71,  // c
		4.32,  // d
		12.02, // e
		2.30,  // f
		2.03,  // g
		5.92,  // h
		7.31,  // i
		0.10,  // j
		0.69,  // k
		3.98,  // l
		2.61,  // m
		6.95,  // n
		7.68,  // o
		1.82,  // p
		0.11,  // q
		6.02,  // r
		6.28,  // s
		9.10,  // t
		2.88,  // u
		1.11,  // v
		2.09,  // w
		0.17,  // x
		2.11,  // y
		0.07,  // z
	}
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

func ScoreEnglishText(text string) (chiSq float64) {
	// Using the chi sq statistic to measure how good the english char frequency
	// distribution fits to the observed character frequency distribution.
	// http://www.stat.yale.edu/Courses/1997-98/101/chigf.htm
	chiSq = 0.0

	text = strings.ToLower(text)
	for i, letter := range alphabetLower {
		numObserved := strings.Count(text, string(letter))
		fracObserved := float64(numObserved) / float64(len(text))
		chiSq += math.Pow(2, fracObserved-englishFrequencies[i]) / englishFrequencies[i]
	}
	return chiSq
}

func BreakSingleCharXOR(ciphertext string) (plaintext string, key string, metric float64) {
	// Ciphertext is hex, first convert to bytes
	ciphertextBytes := ConvertHexToBytes(ciphertext)

	var potentialSolutions = [52]BruteForceSearchPotentialSolution{}

	for i, letter := range alphabetUpperAndLower {
		var buffer bytes.Buffer
		var metric float64
		for _, b := range ciphertextBytes {
			char := b ^ byte(letter)
			buffer.WriteString(string(char))
		}

		// Store this result
		metric = ScoreEnglishText(buffer.String())
		potentialSolutions[i] = BruteForceSearchPotentialSolution{
			plaintext: buffer.String(),
			key:       string(letter),
			metric:    metric,
		}
	}

	// Return the best solution
	bestMetric := potentialSolutions[0].metric
	bestSolution := 0
	for i, solution := range potentialSolutions {
		if solution.metric < bestMetric {
			bestMetric = solution.metric
			bestSolution = i
		}
	}

	plaintext = potentialSolutions[bestSolution].plaintext
	key = potentialSolutions[bestSolution].key
	return plaintext, key, bestMetric
}

func DetectSingleCharXOR(lines []string) {
	for _, line := range lines {
		//fmt.Println(line)
		//plaintext, key, metric := BreakSingleCharXOR(line)
		plaintext, _, _ := BreakSingleCharXOR(line)
		//fmt.Println("line %s....", ind)
		fmt.Println(plaintext)
		//fmt.Printf(key)
		//fmt.Printf("Metric: %s", metric)
	}
}
