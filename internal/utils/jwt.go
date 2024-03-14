package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/internal/interfaces"
	"github.com/kKar1503/thirdweb-auth-go/internal/models"
)

var (
	InvalidJWTFormatError    = errors.New("invalid JWT format")
	InvalidTokenIdError      = errors.New("invalid token id")
	JWTDomainMismatchError   = errors.New("invalid domain in JWT")
	JWTInvalidBeforeError    = errors.New("request time is JWT nbf")
	JWTExpiredError          = errors.New("jWT has expired")
	JWTInvalidIssuerError    = errors.New("invalid JWT issuer")
	JWTInvalidSignatureError = errors.New("invalid JWT signature")
)

// Build JWT token based on the authentication payload
func BuildJWT(
	signVerifier interfaces.SignVerifier,
	input *models.AuthenticationPayloadDataInput,
) (string, error) {
	payload := input.ToData()

	message, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signature, err := signVerifier.SignMessage(string(message))
	if err != nil {
		return "", err
	}

	headerString := `{"alg":"ES256","typ":"JWT"}`

	headerEncoded := base64.StdEncoding.EncodeToString([]byte(headerString))
	payloadEncoded := base64.StdEncoding.EncodeToString(message)
	signatureEncoded := base64.StdEncoding.EncodeToString([]byte(signature))

	jwt := headerEncoded + "." + payloadEncoded + "." + signatureEncoded

	return jwt, nil
}

// Generate a new JWT uing a login payload
func GenerateJWT(
	signVerifier interfaces.SignVerifier,
	payload *models.LoginPayload,
	options *models.GenerateOptions,
	clientOptions *models.ThirdwebAuthOptions,
) (string, error) {
	verifyOptions := options.VerifyOptions
	verifyOptions.Domain = options.Domain

	userAddress, err := VerifyLoginPayload(payload, &verifyOptions, clientOptions)
	if err != nil {
		return "", err
	}

	session := options.Session(userAddress)

	nbf := time.Now().UTC()
	if options.InvalidBefore.IsZero() {
		nbf = options.InvalidBefore
	}

	input := &models.AuthenticationPayloadDataInput{
		ISS: clientOptions.JwtISS,
		SUB: userAddress,
		AUD: options.Domain,
		NBF: nbf,
		EXP: options.ExpirationTime,
		IAT: time.Now().UTC(),
		JTI: options.TokenId,
		CTX: session,
	}

	return BuildJWT(signVerifier, input)
}

// Parse data from an encoded auth JWT
func ParseJWT(jwt string) (*models.AuthenticationPayload, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, InvalidJWTFormatError
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload models.AuthenticationPayloadData
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	return &models.AuthenticationPayload{
		Payload:   &payload,
		Signature: string(signature),
	}, nil
}

// Refresh an existing JWT
func RefreshJWT(
	signVerifier interfaces.SignVerifier,
	jwt string,
	options *models.RefreshOptions,
) (string, error) {
	if options == nil {
		options = models.DefaultRefreshOptions()
	}

	payload, err := ParseJWT(jwt)
	if err != nil {
		return "", err
	}

	return BuildJWT(signVerifier, &models.AuthenticationPayloadDataInput{
		ISS: payload.Payload.ISS,
		SUB: payload.Payload.SUB,
		AUD: payload.Payload.AUD,
		NBF: time.Now().UTC(),
		EXP: options.ExpirationTime,
		IAT: time.Now().UTC(),
		CTX: payload.Payload.CTX,
	})
}

// Validate a JWT and extract the user's info
func AuthenticateJWT(
	jwt string,
	options *models.AuthenticateOptions,
	clientOptions *models.ThirdwebAuthOptions,
) (*models.User, error) {
	payload, err := ParseJWT(jwt)
	if err != nil {
		return nil, err
	}

	if err := options.ValidateTokenId(payload.Payload.JTI); err != nil {
		return nil, InvalidTokenIdError
	}

	if payload.Payload.AUD != options.Domain {
		return nil, JWTDomainMismatchError
	}

	timeNow := time.Now().UTC().Unix()

	if payload.Payload.NBF > timeNow {
		return nil, JWTInvalidBeforeError
	}

	if payload.Payload.EXP < timeNow {
		return nil, JWTExpiredError
	}

	if strings.EqualFold(payload.Payload.ISS, clientOptions.JwtISS) {
		return nil, JWTInvalidIssuerError
	}

	jsonPayload, err := json.Marshal(payload.Payload)
	if err != nil {
		return nil, err
	}

	verified, err := VerifySignature(
		string(jsonPayload),
		payload.Signature,
		clientOptions.JwtISS,
		clientOptions.ClientID,
		clientOptions.ClientSecret,
	)
	if err != nil || !verified {
		return nil, JWTInvalidSignatureError
	}

	return &models.User{
		Address: payload.Payload.SUB,
		Session: payload.Payload.CTX,
	}, nil
}
