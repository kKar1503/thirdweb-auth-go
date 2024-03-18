package signverifier

import (
	"crypto/hmac"
	"crypto/sha256"
)

type BasicSignVerifier struct {
	privateKey []byte
}

func NewBasicSignVerifier(privateKey []byte) *BasicSignVerifier {
	return &BasicSignVerifier{privateKey: privateKey}
}

func (s *BasicSignVerifier) SignMessage(message string) (string, error) {
	h := hmac.New(sha256.New, s.privateKey)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", err
	}
	signature := h.Sum(nil)
	return string(signature), nil
}

func (s *BasicSignVerifier) VerifySignature(message, signature string) (bool, error) {
	h := hmac.New(sha256.New, s.privateKey)
	_, err := h.Write([]byte(message))
	if err != nil {
		return false, err
	}
	expectedSignature := h.Sum(nil)
	return hmac.Equal(expectedSignature, []byte(signature)), nil
}
