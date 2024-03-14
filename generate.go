package thirdwebauth

import "time"

type GenerateOptions struct {
	Domain         string                   `json:"domain,omitempty"`
	TokenId        string                   `json:"tokenId,omitempty"`
	ExpirationTime time.Time                `json:"expirationTime"`
	InvalidBefore  time.Time                `json:"invalidBefore,omitempty"`
	Session        func(string) interface{} `json:"session,omitempty"`
	VerifyOptions  VerifyOptions            `json:"verifyOptions,omitempty"`
}

func DefaultGenerateOptions() *GenerateOptions {
	return &GenerateOptions{
		ExpirationTime: time.Now().UTC().Add(DefaultTokenDuration),
	}
}
