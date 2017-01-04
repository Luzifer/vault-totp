package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

type token struct {
	Name   string
	Secret string
}

func (t token) GetCode(in time.Time) (string, error) {
	return totp.GenerateCode(strings.ToUpper(t.Secret), in)
}

func (t token) BuildOutput(showName bool) (string, error) {
	// Output: "123456 (Valid 12s)", "123456 (Valid 1s)"

	n := time.Now()
	code, err := t.GetCode(n)
	if err != nil {
		return "", err
	}

	var output string
	if showName {
		output = fmt.Sprintf("%s: ", t.Name)
	}

	output = fmt.Sprintf("%s%s", output, code)

	if !cfg.NoTime {
		remain := 30 - (n.Second() % 30)
		output = fmt.Sprintf("%s (Valid %ds) ", output, remain)
	}

	return output, nil
}

// Sorter interface

type tokenList []token

func (t tokenList) Len() int           { return len(t) }
func (t tokenList) Less(i, j int) bool { return t[i].Name < t[j].Name }
func (t tokenList) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }
