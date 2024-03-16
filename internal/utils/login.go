package utils

import (
	"errors"
	"fmt"
	"slices"
	"time"

	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
)

const (
	typeField    = "Ethereum"
	headerFormat = "%s wants you to sign in with your %s account:" // domain, typeField
)

var (
	PayloadDomainMismatchError    = errors.New("payload domain does not match the domain in the options")
	PayloadStatementMismatchError = errors.New("payload statement does not match the statement in the options")
	PayloadURIMismatchError       = errors.New("payload URI does not match the URI in the options")
	PayloadVersionMismatchError   = errors.New("payload version does not match the version in the options")
	PayloadChainIDMismatchError   = errors.New("payload chainID does not match the chainID in the options")
	PayloadNonceError             = errors.New("login request nonce is invalid")
	PayloadInvalidBeforeError     = errors.New("payload invalid_before is invalid")
	PayloadNotYetValidError       = errors.New("login request is not yet valid")
	PayloadExpirationTimeError    = errors.New("payload expiration_time is invalid")
	PayloadExpiredError           = errors.New("login request has expired")
	PayloadMissingResourcesError  = errors.New("login request is missing required resources")
	PayloadInvalidSignatureError  = errors.New("login request signature is invalid")
)

// Create an EIP-4361 & CAIP-122 compliant message to sign based on the login payload
func CreateLoginMessage(payload *thirdwebauth.LoginPayloadData) string {
	prefix := fmt.Sprintf(headerFormat, payload.Domain, typeField)
	if payload.Address != "" {
		prefix += "\n" + payload.Address
	}

	if payload.Statement != "" {
		prefix += "\n\n" + payload.Statement + "\n"
	}

	suffix := ""

	if payload.URI != "" {
		suffix += "\n" + payload.URI
	}

	suffix += "\nVersion: " + payload.Version

	suffix += "\nNonce: " + payload.Nonce

	suffix += "\nIssued At: " + payload.IssuedAt

	suffix += "\nExpiration Time: " + payload.ExpirationTime

	if payload.InvalidBefore != "" {
		suffix += "\nNot Before: " + payload.InvalidBefore
	}

	if len(payload.Resources) > 0 {
		suffix += "\nResources:"
		for _, resource := range payload.Resources {
			suffix += "\n- " + resource
		}
	}

	fullMessage := prefix
	if suffix != "" {
		fullMessage = "\n" + suffix
	}

	return fullMessage
}

func BuildLoginPayload(options *thirdwebauth.LoginOptions) *thirdwebauth.LoginPayloadData {
	payload := thirdwebauth.DefaultLoginPayloadData()

	payload.Domain = options.Domain
	payload.ChainID = options.ChainID
	payload.ExpirationTime = options.ExpirationTime.UTC().Format(time.RFC3339)
	payload.InvalidBefore = options.InvalidBefore.UTC().Format(time.RFC3339)

	if options.Address != "" {
		payload.Address = options.Address
	}

	if options.Statement != "" {
		payload.Statement = options.Statement
	}

	if options.Version != "" {
		payload.Version = options.Version
	}

	if options.URI != "" {
		payload.URI = options.URI
	}

	if options.Nonce != "" {
		payload.Nonce = options.Nonce
	}

	if len(options.Resources) > 0 {
		payload.Resources = options.Resources
	}

	return payload
}

func SignLoginPayload(
	signVerifier thirdwebauth.SignVerifier,
	payload *thirdwebauth.LoginPayloadData,
) (*thirdwebauth.LoginPayload, error) {
	message := CreateLoginMessage(payload)
	signature, err := signVerifier.SignMessage(message)
	if err != nil {
		return nil, err
	}

	return &thirdwebauth.LoginPayload{
		Payload:   payload,
		Signature: signature,
	}, nil
}

func BuildAndSignLoginPayload(
	signVerifier thirdwebauth.SignVerifier,
	options *thirdwebauth.LoginOptions,
) (*thirdwebauth.LoginPayload, error) {
	payload := BuildLoginPayload(options)
	return SignLoginPayload(signVerifier, payload)
}

func VerifyLoginPayload(
	payload *thirdwebauth.LoginPayload,
	options *thirdwebauth.VerifyOptions,
	clientOptions *thirdwebauth.ThirdwebAuthOptions,
) (string, error) {
	if payload.Payload.Domain != options.Domain {
		return "", PayloadDomainMismatchError
	}

	if options.Statement != "" && payload.Payload.Statement != options.Statement {
		return "", PayloadStatementMismatchError
	}

	if options.URI != "" && payload.Payload.URI != options.URI {
		return "", PayloadURIMismatchError
	}

	if options.Version != "" && payload.Payload.Version != options.Version {
		return "", PayloadVersionMismatchError
	}

	if options.ChainID != "" && payload.Payload.ChainID != options.ChainID {
		return "", PayloadChainIDMismatchError
	}

	if err := options.ValidateNonce(payload.Payload.Nonce); err != nil {
		return "", PayloadNonceError
	}

	timeNow := time.Now().UTC()

	if invalidBefore, err := time.Parse(time.RFC3339, payload.Payload.InvalidBefore); err != nil {
		return "", PayloadInvalidBeforeError
	} else if timeNow.Before(invalidBefore) {
		return "", PayloadNotYetValidError
	}

	if expirationTime, err := time.Parse(time.RFC3339, payload.Payload.ExpirationTime); err != nil {
		return "", PayloadExpirationTimeError
	} else if timeNow.After(expirationTime) {
		return "", PayloadExpiredError
	}

	if len(options.Resources) > 0 {
		if len(payload.Payload.Resources) == 0 {
			return "", PayloadMissingResourcesError
		}

		for _, resource := range options.Resources {
			if !slices.Contains(payload.Payload.Resources, resource) {
				return "", PayloadMissingResourcesError
			}
		}
	}

	message := CreateLoginMessage(payload.Payload)

	verified, err := VerifySignature(
		message,
		payload.Signature,
		payload.Payload.Address,
		clientOptions.ClientID,
		clientOptions.ClientSecret,
	)
	if err != nil || !verified {
		return "", PayloadInvalidSignatureError
	}

	return payload.Payload.Address, nil
}
