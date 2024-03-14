package handlers

import (
	"net/http"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
	internalModels "github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

func LoginHandler(c echo.Context, authCtx *models.ThirdwebAuthContext) (err error) {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	payload := &models.LoginPayloadBody{}
	if err = c.Bind(payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid login payload"})
	}

	generateOptions := &internalModels.GenerateOptions{
		VerifyOptions: internalModels.VerifyOptions{
			Statement:     authCtx.AuthOptions.Statement,
			URI:           authCtx.AuthOptions.URI,
			Version:       authCtx.AuthOptions.Version,
			ChainID:       authCtx.AuthOptions.ChainID,
			ValidateNonce: validateNonce(authCtx),
			Resources:     authCtx.AuthOptions.Resources,
		},
		Session: getSession(c, authCtx),
	}

	if authCtx.AuthOptions.TokenDuration != 0 {
		generateOptions.ExpirationTime = time.Now().Add(authCtx.AuthOptions.TokenDuration)
	}

	token, err := authCtx.Auth.Generate(&payload.Payload, generateOptions)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if authCtx.Callbacks.OnToken != nil {
		authCtx.Callbacks.OnToken(c, token)
	}

	parsedToken, err := authCtx.Auth.ParseToken(token)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	authTokenCookie := &http.Cookie{
		Name:     globals.AuthTokenCookiePrefix + "_" + payload.Payload.Payload.Address,
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Unix(parsedToken.Payload.EXP, 0),
		HttpOnly: true,
		Secure:   true,
	}
	if authCtx.CookieOptions.Domain != nil {
		authTokenCookie.Domain = *authCtx.CookieOptions.Domain
	}
	if authCtx.CookieOptions.Path != nil {
		authTokenCookie.Path = *authCtx.CookieOptions.Path
	}
	if authCtx.CookieOptions.SameSite != nil {
		authTokenCookie.SameSite = *authCtx.CookieOptions.SameSite
	}
	if authCtx.CookieOptions.Secure != nil {
		authTokenCookie.Secure = *authCtx.CookieOptions.Secure
	}
	c.SetCookie(authTokenCookie)

	activeAccountCookie := &http.Cookie{
		Name:     globals.AuthActiveAccountCookie,
		Value:    payload.Payload.Payload.Address,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Unix(parsedToken.Payload.EXP, 0),
		HttpOnly: true,
		Secure:   true,
	}
	if authCtx.CookieOptions.Domain != nil {
		activeAccountCookie.Domain = *authCtx.CookieOptions.Domain
	}
	if authCtx.CookieOptions.Path != nil {
		activeAccountCookie.Path = *authCtx.CookieOptions.Path
	}
	if authCtx.CookieOptions.SameSite != nil {
		activeAccountCookie.SameSite = *authCtx.CookieOptions.SameSite
	}
	if authCtx.CookieOptions.Secure != nil {
		activeAccountCookie.Secure = *authCtx.CookieOptions.Secure
	}
	c.SetCookie(activeAccountCookie)

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

func validateNonce(authCtx *models.ThirdwebAuthContext) func(string) error {
	return func(nonce string) error {
		if authCtx.AuthOptions.ValidateNonce != nil {
			return authCtx.AuthOptions.ValidateNonce(nonce)
		}

		return nil
	}
}

func getSession(c echo.Context, authCtx *models.ThirdwebAuthContext) func(string) interface{} {
	return func(address string) interface{} {
		if authCtx.Callbacks.OnLogin != nil {
			return authCtx.Callbacks.OnLogin(c, address)
		}

		return nil
	}
}
