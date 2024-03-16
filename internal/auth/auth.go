package auth

import (
	"time"

	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
	"github.com/kKar1503/thirdweb-auth-go/internal/utils"
)

type ThirdwebAuth struct {
	domain   string                           // domain of app
	verifier thirdwebauth.SignVerifier        // used to sign and verify tokens
	options  thirdwebauth.ThirdwebAuthOptions // options for the auth server
}

func NewThirdwebAuth(domain string, verifier thirdwebauth.SignVerifier) *ThirdwebAuth {
	return &ThirdwebAuth{
		domain:   domain,
		verifier: verifier,
	}
}

func (a *ThirdwebAuth) WithOptions(options thirdwebauth.ThirdwebAuthOptions) *ThirdwebAuth {
	a.options = options
	return a
}

func (a *ThirdwebAuth) Payload(
	options *thirdwebauth.LoginOptions,
) *thirdwebauth.LoginPayloadData {
	if options == nil {
		options = thirdwebauth.DefaultLoginOptions()
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.BuildLoginPayload(options)
}

func (a *ThirdwebAuth) LoginWithPayload(
	payload *thirdwebauth.LoginPayloadData,
) (*thirdwebauth.LoginPayload, error) {
	return utils.SignLoginPayload(a.verifier, payload)
}

func (a *ThirdwebAuth) Login(
	options *thirdwebauth.LoginOptions,
) (*thirdwebauth.LoginPayload, error) {
	if options == nil {
		options = thirdwebauth.DefaultLoginOptions()
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.BuildAndSignLoginPayload(a.verifier, options)
}

func (a *ThirdwebAuth) Verify(
	payload *thirdwebauth.LoginPayload,
	options *thirdwebauth.VerifyOptions,
) (string, error) {
	if options == nil {
		options = &thirdwebauth.VerifyOptions{
			Domain: a.domain,
		}
	} else if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.VerifyLoginPayload(payload, options, &a.options)
}

func (a *ThirdwebAuth) Generate(
	payload *thirdwebauth.LoginPayload,
	options *thirdwebauth.GenerateOptions,
) (string, error) {
	if options == nil {
		options = thirdwebauth.DefaultGenerateOptions()
	}

	return utils.GenerateJWT(a.verifier, payload, options, &a.options)
}

func (a *ThirdwebAuth) Refresh(
	jwt string,
	expirationTime *time.Time,
) (string, error) {
	refreshOptions := thirdwebauth.DefaultRefreshOptions()
	if expirationTime != nil {
		refreshOptions.ExpirationTime = *expirationTime
	}

	return utils.RefreshJWT(a.verifier, jwt, refreshOptions)
}

func (a *ThirdwebAuth) Authenticate(
	jwt string,
	options *thirdwebauth.AuthenticateOptions,
) (*thirdwebauth.User, error) {
	if options == nil {
		options = &thirdwebauth.AuthenticateOptions{}
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.AuthenticateJWT(jwt, options, &a.options)
}

func (a *ThirdwebAuth) ParseToken(jwt string) (*thirdwebauth.AuthenticationPayload, error) {
	return utils.ParseJWT(jwt)
}
