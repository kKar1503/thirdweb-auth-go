package thirdwebauth

import (
	"time"

	"github.com/google/uuid"
)

type LoginOptions struct {
	Domain         string    `json:"domain,omitempty"`
	Address        string    `json:"address,omitempty"`
	Statement      string    `json:"statement,omitempty"`
	URI            string    `json:"uri,omitempty"`
	Version        string    `json:"version,omitempty"`
	ChainID        string    `json:"chainId,omitempty"`
	Nonce          string    `json:"nonce,omitempty"`
	ExpirationTime time.Time `json:"expirationTime,omitempty"`
	InvalidBefore  time.Time `json:"invalidBefore,omitempty"`
	Resources      []string  `json:"resources,omitempty"`
}

func DefaultLoginOptions() *LoginOptions {
	return &LoginOptions{
		ExpirationTime: time.Now().UTC().Add(DefaultLoginPayloadDuration),
		InvalidBefore:  time.Now().UTC().Add(-DefaultLoginPayloadDuration),
	}
}

type LoginPayloadData struct {
	Type           string   `json:"type"                      validate:"required"`
	Domain         string   `json:"domain"                    validate:"required"`
	Address        string   `json:"address"                   validate:"required"`
	Statement      string   `json:"statement"                 validate:"required"`
	URI            string   `json:"uri,omitempty"`
	Version        string   `json:"version"                   validate:"required"`
	ChainID        string   `json:"chain_id,omitempty"`
	Nonce          string   `json:"nonce"                     validate:"required"`
	IssuedAt       string   `json:"issued_at"                 validate:"required"`
	ExpirationTime string   `json:"expiration_time,omitempty"`
	InvalidBefore  string   `json:"invalid_before"            validate:"required"`
	Resources      []string `json:"resources,omitempty"`
}

func DefaultLoginPayloadData() *LoginPayloadData {
	return &LoginPayloadData{
		Type:          "evm",
		Statement:     "Please ensure that the domain above matches the URL of the current website.",
		Version:       "1",
		Nonce:         uuid.NewString(),
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		InvalidBefore: time.Now().UTC().Format(time.RFC3339),
	}
}

type LoginPayload struct {
	Payload   *LoginPayloadData `json:"payload"   validate:"required"`
	Signature string            `json:"signature" validate:"required"`
}

type User struct {
	Address string      `json:"address"           validate:"required"`
	Session interface{} `json:"session,omitempty"`
}
