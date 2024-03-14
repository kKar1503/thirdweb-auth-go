package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
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
		ExpirationTime: time.Now().UTC().Add(globals.DefaultLoginPayloadDuration),
		InvalidBefore:  time.Now().UTC().Add(-globals.DefaultLoginPayloadDuration),
	}
}

type LoginPayloadData struct {
	Type           string   `json:"type"`
	Domain         string   `json:"domain"`
	Address        string   `json:"address"`
	Statement      string   `json:"statement"`
	URI            string   `json:"uri,omitempty"`
	Version        string   `json:"version"`
	ChainID        string   `json:"chain_id,omitempty"`
	Nonce          string   `json:"nonce"`
	IssuedAt       string   `json:"issued_at"`
	ExpirationTime string   `json:"expiration_time,omitempty"`
	InvalidBefore  string   `json:"invalid_before"`
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
	Payload   *LoginPayloadData `json:"payload"`
	Signature string            `json:"signature"`
}

type User struct {
	Address string      `json:"address"`
	Session interface{} `json:"session,omitempty"`
}
