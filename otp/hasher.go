package otp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nakhostin/gox/otp/algorithm"
)

func build(
	code string,
	expiresAt int64,
	payload map[string]any,
	secret string,
	algh algorithm.Algorithm,
) (string, error) {

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	raw := fmt.Sprintf(
		"%s:%d:%s:%s",
		code,
		expiresAt,
		payloadBytes,
		secret,
	)

	switch algh {
	case algorithm.AlgorithmHMACSHA256:
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	case algorithm.AlgorithmHMACSHA512:
		sum := sha512.Sum512([]byte(raw))
		return hex.EncodeToString(sum[:]), nil
	default:
		return raw, nil
	}
}
