package gocryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"strings"
)

const (
	alphabetLower = "abcdefghijklmnopqrstuvwxyz"
	alphabetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numerals      = "0123456789"
	allAscii      = alphabetLower + alphabetUpper + numerals + " ~!@#$%^&*()-_+={}[]\\|<,>.?/\"';:`"
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

func ConvertBase64ToAscii(base64String string) (asciiBytes []byte) {
	asciiBytes, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		log.Println("error decoding base64 string: ", err)
	}
	return asciiBytes
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

func FixedXOR(firstBytes []byte, secondBytes []byte) (result []byte) {
	// Bail if they are different lengths
	if len(firstBytes) != len(secondBytes) {
		log.Println("strings are not the same length")
		return
	}

	// Now XOR byte by byte and store result back in firstBytes
	for i, b := range secondBytes {
		firstBytes[i] ^= b
	}
	return firstBytes
}

type BruteForceSearchPotentialSolution struct {
	plaintext string
	key       string
	metric    float64
}

func FindBestBruteForceSolution(potentialSolutions []BruteForceSearchPotentialSolution) (plaintext string, key string, bestMetric float64) {
	// Return the best solution
	bestMetric = potentialSolutions[0].metric
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

func ScoreEnglishText(text string) (chiSq float64) {
	// Using the chi sq statistic to measure how good the english char frequency
	// distribution fits to the observed character frequency distribution.
	// http://www.stat.yale.edu/Courses/1997-98/101/chigf.htm
	chiSq = 0.0

	for i, letter := range alphabetLower {
		numObserved := strings.Count(text, string(letter))
		fracObserved := float64(numObserved) / float64(len(text))
		chiSq += math.Pow(fracObserved-englishFrequencies[i], 2) / englishFrequencies[i]
	}
	return chiSq
}

func BreakSingleCharXOR(ciphertext string) (plaintext string, key string, metric float64) {
	// Ciphertext is hex, first convert to bytes
	ciphertextBytes := ConvertHexToBytes(ciphertext)

	var potentialSolutions []BruteForceSearchPotentialSolution

	for _, letter := range allAscii {
		var metric float64
		var plaintextBytes []byte
		for _, b := range ciphertextBytes {
			char := b ^ byte(letter)
			plaintextBytes = append(plaintextBytes, char)
		}

		metric = ScoreEnglishText(string(plaintextBytes))
		potentialSolution := BruteForceSearchPotentialSolution{
			plaintext: string(plaintextBytes),
			key:       string(letter),
			metric:    metric,
		}
		potentialSolutions = append(potentialSolutions, potentialSolution)
	}

	plaintext, key, bestMetric := FindBestBruteForceSolution(potentialSolutions)
	return plaintext, key, bestMetric
}

func DetectSingleCharXOR(lines []string) (plaintext string, key string, metric float64) {
	var potentialSolutions []BruteForceSearchPotentialSolution

	for _, line := range lines {
		plaintext, key, metric := BreakSingleCharXOR(line)

		potentialSolution := BruteForceSearchPotentialSolution{
			plaintext: plaintext,
			key:       key,
			metric:    metric,
		}
		potentialSolutions = append(potentialSolutions, potentialSolution)
	}

	plaintext, key, bestMetric := FindBestBruteForceSolution(potentialSolutions)
	return plaintext, key, bestMetric
}

func RepeatingKeyXOR(plaintext string, key string) (ciphertextHex string) {
	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)

	timesKeyRepeats := len(plaintextBytes) / len(keyBytes)
	numberBytesLeftover := len(plaintextBytes) % len(keyBytes)

	var fullKeyBytes []byte

	for i := 0; i < timesKeyRepeats; i++ {
		for _, keyByte := range keyBytes {
			fullKeyBytes = append(fullKeyBytes, keyByte)
		}
	}

	for j := 0; j < numberBytesLeftover; j++ {
		fullKeyBytes = append(fullKeyBytes, keyBytes[j])
	}

	// Now XOR together the plaintext and key and store back in plaintextBytes
	for i, b := range fullKeyBytes {
		plaintextBytes[i] ^= b
	}

	ciphertextHex = ConvertBytesToHex(plaintextBytes)
	return ciphertextHex
}

func ComputeEditDistance(firstStringBytes []byte, secondStringBytes []byte) (editDistance int) {
	if len(firstStringBytes) != len(secondStringBytes) {
		fmt.Printf("strings must be the same length")
	}

	for i, _ := range firstStringBytes {
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint(j))
			if (firstStringBytes[i] & mask) != (secondStringBytes[i] & mask) {
				editDistance++
			}
		}
	}
	return editDistance
}

func BreakRepeatingKeyXOR(ciphertext []byte) (reconstructedKey string) {
	// First, we determine the key size that was used to encrypt the text.
	bestEditDistance := 1000.00 // initialize to high value
	var bestKeySize int
	for keySize := 1; keySize <= 40; keySize++ {
		// Step through entire ciphertext to compute the mean hamming distance
		numFragments := len(ciphertext) / keySize
		sumEditDistance := 0.0

		for i := 1; i <= numFragments; i++ {
			sumEditDistance += float64(ComputeEditDistance(ciphertext[(i-1)*keySize:i*keySize],
				ciphertext[i*keySize:(i+1)*keySize]))
		}

		averageEditDistance := float64(sumEditDistance) / float64(numFragments)
		normalizedEditDistance := averageEditDistance / float64(keySize)

		// Is this the best key size observed so far?
		if normalizedEditDistance < bestEditDistance {
			bestEditDistance = normalizedEditDistance
			bestKeySize = keySize
		}
	}

	// Second, we break up the ciphertext into single char XOR problems and solve.
	numChunks := len(ciphertext) / bestKeySize

	for k := 0; k < bestKeySize; k++ {
		var ciphertextChunk []byte
		for i := 1; i <= numChunks; i++ {
			beginningIndex := (i - 1) * bestKeySize
			endingIndex := i * bestKeySize
			ciphertextKeyLen := ciphertext[beginningIndex:endingIndex]
			ciphertextChunk = append(ciphertextChunk, ciphertextKeyLen[k])
		}
		_, key, _ := BreakSingleCharXOR(ConvertBytesToHex(ciphertextChunk))
		reconstructedKey += key
	}
	return reconstructedKey
}
