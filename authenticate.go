package thirdwebauth

import (
	"time"

	"github.com/google/uuid"
)

type AuthenticationPayloadDataInput struct {
	ISS string      `json:"iss"`
	SUB string      `json:"sub"`
	AUD string      `json:"aud"`
	EXP time.Time   `json:"exp"`
	NBF time.Time   `json:"nbf"`
	IAT time.Time   `json:"iat"`
	JTI string      `json:"jti"`
	CTX interface{} `json:"ctx"`
}

func DefaultAuthenticationPayloadDataInput() *AuthenticationPayloadDataInput {
	return &AuthenticationPayloadDataInput{
		JTI: uuid.NewString(),
	}
}

type AuthenticationPayloadData struct {
	ISS string      `json:"iss"`
	SUB string      `json:"sub"`
	AUD string      `json:"aud"`
	EXP int64       `json:"exp"`
	NBF int64       `json:"nbf"`
	IAT int64       `json:"iat"`
	JTI string      `json:"jti"`
	CTX interface{} `json:"ctx"`
}

func (input *AuthenticationPayloadDataInput) ToData() *AuthenticationPayloadData {
	d := &AuthenticationPayloadData{}
	d.ISS = input.ISS
	d.SUB = input.SUB
	d.AUD = input.AUD
	d.EXP = input.EXP.Unix()
	d.NBF = input.NBF.Unix()
	d.IAT = input.IAT.Unix()
	d.JTI = input.JTI
	d.CTX = input.CTX
	return d
}

type AuthenticationPayload struct {
	Payload   *AuthenticationPayloadData `json:"payload"`
	Signature string                     `json:"signature"`
}

type AuthenticateOptions struct {
	Domain          string             `json:"domain,omitempty"`
	ValidateTokenId func(string) error `json:"-"`
}
