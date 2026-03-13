package pgwire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var cryptoRandReader io.Reader = rand.Reader

type serverFirstParsed struct {
	nonce      string
	salt       []byte
	iterations int
}

type serverFinalParsed struct {
	verifier []byte
}

func parseServerFirst(msg string) (*serverFirstParsed, error) {
	var result serverFirstParsed

	for _, part := range strings.Split(msg, ",") {
		if strings.HasPrefix(part, "r=") {
			result.nonce = part[2:]
		} else if strings.HasPrefix(part, "s=") {
			salt, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return nil, fmt.Errorf("decode salt: %w", err)
			}
			result.salt = salt
		} else if strings.HasPrefix(part, "i=") {
			iter, err := strconv.Atoi(part[2:])
			if err != nil {
				return nil, fmt.Errorf("parse iterations: %w", err)
			}
			result.iterations = iter
		}
	}

	if result.nonce == "" || result.salt == nil || result.iterations == 0 {
		return nil, fmt.Errorf("incomplete server-first-message: %q", msg)
	}

	return &result, nil
}

func parseServerFinal(msg string) (*serverFinalParsed, error) {
	if strings.HasPrefix(msg, "e=") {
		return nil, fmt.Errorf("SCRAM server error: %s", msg[2:])
	}
	if !strings.HasPrefix(msg, "v=") {
		return nil, fmt.Errorf("unexpected server-final format: %q", msg)
	}
	verifier, err := base64.StdEncoding.DecodeString(msg[2:])
	if err != nil {
		return nil, fmt.Errorf("decode verifier: %w", err)
	}
	return &serverFinalParsed{verifier: verifier}, nil
}

// hi implements the SCRAM Hi() function (PBKDF2 with HMAC-SHA-256).
func hi(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		xorBytesInto(result, u)
	}

	return result
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func xorBytesInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func saslPrepUsername(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}

func saslPrepPassword(s string) string {
	// SASLprep is complex; for typical passwords this passthrough is adequate.
	return s
}
