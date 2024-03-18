package thirdwebauth

import (
	"time"

	"github.com/google/uuid"
)

type AuthenticationPayloadDataInput struct {
	ISS string      `json:"iss" validate:"required"`
	SUB string      `json:"sub" validate:"required"`
	AUD string      `json:"aud" validate:"required"`
	EXP time.Time   `json:"exp" validate:"required"`
	NBF time.Time   `json:"nbf" validate:"required"`
	IAT time.Time   `json:"iat" validate:"required"`
	JTI string      `json:"jti" validate:"required"`
	CTX interface{} `json:"ctx"`
}

func DefaultAuthenticationPayloadDataInput() *AuthenticationPayloadDataInput {
	return &AuthenticationPayloadDataInput{
		JTI: uuid.NewString(),
	}
}

type AuthenticationPayloadData struct {
	ISS string      `json:"iss" validate:"required"`
	SUB string      `json:"sub" validate:"required"`
	AUD string      `json:"aud" validate:"required"`
	EXP int64       `json:"exp" validate:"required"`
	NBF int64       `json:"nbf" validate:"required"`
	IAT int64       `json:"iat" validate:"required"`
	JTI string      `json:"jti" validate:"required"`
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
	Payload   *AuthenticationPayloadData `json:"payload"   validate:"required"`
	Signature string                     `json:"signature" validate:"required"`
}

type AuthenticateOptions struct {
	Domain          string             `json:"domain,omitempty"`
	ValidateTokenId func(string) error `json:"-"`
}
