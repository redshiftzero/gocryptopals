package gocryptopals

import (
  "math/rand"
  "time"
  "strings"
)


func PickRandomLine(content []byte) (selectedLine []byte) {
    lines := strings.Split(string(content), "\n")
    rand.Seed(time.Now().Unix())
    index := RandomInt(0, len(lines) - 1)
    selectedLine = []byte(lines[index])
    return selectedLine
}
