package auth

import (
	"time"

	"github.com/kKar1503/thirdweb-auth-go/internal/interfaces"
	"github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/kKar1503/thirdweb-auth-go/internal/utils"
)

type ThirdwebAuth struct {
	domain   string                     // domain of app
	verifier interfaces.SignVerifier    // used to sign and verify tokens
	options  models.ThirdwebAuthOptions // options for the auth server
}

func NewThirdwebAuth(domain string, verifier interfaces.SignVerifier) *ThirdwebAuth {
	return &ThirdwebAuth{
		domain:   domain,
		verifier: verifier,
	}
}

func (a *ThirdwebAuth) WithOptions(options models.ThirdwebAuthOptions) *ThirdwebAuth {
	a.options = options
	return a
}

func (a *ThirdwebAuth) Payload(
	options *models.LoginOptions,
) *models.LoginPayloadData {
	if options == nil {
		options = models.DefaultLoginOptions()
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.BuildLoginPayload(options)
}

func (a *ThirdwebAuth) LoginWithPayload(
	payload *models.LoginPayloadData,
) (*models.LoginPayload, error) {
	return utils.SignLoginPayload(a.verifier, payload)
}

func (a *ThirdwebAuth) Login(
	options *models.LoginOptions,
) (*models.LoginPayload, error) {
	if options == nil {
		options = models.DefaultLoginOptions()
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.BuildAndSignLoginPayload(a.verifier, options)
}

func (a *ThirdwebAuth) Verify(
	payload *models.LoginPayload,
	options *models.VerifyOptions,
) (string, error) {
	if options == nil {
		options = &models.VerifyOptions{
			Domain: a.domain,
		}
	} else if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.VerifyLoginPayload(payload, options, &a.options)
}

func (a *ThirdwebAuth) Generate(
	payload *models.LoginPayload,
	options *models.GenerateOptions,
) (string, error) {
	if options == nil {
		options = models.DefaultGenerateOptions()
	}

	return utils.GenerateJWT(a.verifier, payload, options, &a.options)
}

func (a *ThirdwebAuth) Refresh(
	jwt string,
	expirationTime *time.Time,
) (string, error) {
	refreshOptions := models.DefaultRefreshOptions()
	if expirationTime != nil {
		refreshOptions.ExpirationTime = *expirationTime
	}

	return utils.RefreshJWT(a.verifier, jwt, refreshOptions)
}

func (a *ThirdwebAuth) Authenticate(
	jwt string,
	options *models.AuthenticateOptions,
) (*models.User, error) {
	if options == nil {
		options = &models.AuthenticateOptions{}
	}

	if options.Domain == "" {
		options.Domain = a.domain
	}

	return utils.AuthenticateJWT(jwt, options, &a.options)
}

func (a *ThirdwebAuth) ParseToken(jwt string) (*models.AuthenticationPayload, error) {
	return utils.ParseJWT(jwt)
}
