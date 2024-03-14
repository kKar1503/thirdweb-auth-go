package handlers

import (
	"net/http"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/helpers"
	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

func UserHandler(
	c echo.Context,
	authCtx *models.ThirdwebAuthContext,
) error {
	if c.Request().Method != "GET" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only GET supported."})
	}

	user, err := helpers.GetUser(c, authCtx)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if user != nil {
		token := helpers.GetToken(c)
		if token != "" {
			payload, err := authCtx.Auth.ParseToken(token)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}

			refreshInterval := globals.DefaultRefreshInterval
			if authCtx.AuthOptions.RefreshInterval != 0 {
				refreshInterval = authCtx.AuthOptions.RefreshInterval
			}

			refreshDate := time.Unix(payload.Payload.IAT, 0).Add(refreshInterval)
			if time.Now().After(refreshDate) {
				var expirationTime *time.Time
				if authCtx.AuthOptions.TokenDuration != 0 {
					expirationTime2 := time.Now().Add(authCtx.AuthOptions.TokenDuration)
					expirationTime = &expirationTime2
				}
				refreshToken, err := authCtx.Auth.Refresh(token, expirationTime)
				if err != nil {
					return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
				}
				refreshPayload, err := authCtx.Auth.ParseToken(refreshToken)
				if err != nil {
					return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
				}

				tokenCookie := &http.Cookie{
					Name:     globals.AuthTokenCookiePrefix + "_" + user.Address,
					Value:    refreshToken,
					Path:     "/",
					Expires:  time.Unix(refreshPayload.Payload.EXP, 0),
					SameSite: http.SameSiteNoneMode,
					HttpOnly: true,
					Secure:   true,
				}
				if authCtx.CookieOptions.Domain != nil {
					tokenCookie.Domain = *authCtx.CookieOptions.Domain
				}
				if authCtx.CookieOptions.Path != nil {
					tokenCookie.Path = *authCtx.CookieOptions.Path
				}
				if authCtx.CookieOptions.SameSite != nil {
					tokenCookie.SameSite = *authCtx.CookieOptions.SameSite
				}
				if authCtx.CookieOptions.Secure != nil {
					tokenCookie.Secure = *authCtx.CookieOptions.Secure
				}
				c.SetCookie(tokenCookie)

				activeAccountCookie := &http.Cookie{
					Name:     globals.AuthActiveAccountCookie,
					Value:    user.Address,
					Path:     "/",
					Expires:  time.Unix(refreshPayload.Payload.EXP, 0),
					SameSite: http.SameSiteNoneMode,
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
			}
		}
	}

	return c.JSON(http.StatusOK, user)
}
