package otp

import (
	"crypto/rand"
	"errors"
)

const (
	Digits       = "0123456789"
	Lowercase    = "abcdefghijklmnopqrstuvwxyz"
	Uppercase    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Letters      = Lowercase + Uppercase
	AlphaNumeric = Letters + Digits
)

func generate(length int, charset string) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid length")
	}

	if len(charset) < 2 {
		return "", errors.New("charset must contain at least 2 characters")
	}

	result := make([]byte, length)

	charsetLen := byte(len(charset))
	maxrb := byte(256 - (256 % int(charsetLen)))

	buf := make([]byte, length)

	for i := 0; i < length; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}

		for _, b := range buf {
			if b >= maxrb {
				continue
			}

			result[i] = charset[b%charsetLen]
			i++

			if i == length {
				return string(result), nil
			}
		}
	}

	return string(result), nil
}
