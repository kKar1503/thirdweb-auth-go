package handlers

import (
	"net/http"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/helpers"
	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

func SwitchAccountHandler(c echo.Context, authCtx *models.ThirdwebAuthContext) error {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	activeBody := &models.ActiveBody{}
	if err := c.Bind(activeBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Please provide an address"})
	}

	var cookieExpiration time.Time
	cookie := helpers.GetCookie(c, globals.AuthTokenCookiePrefix+"_"+activeBody.Address)
	if cookie != "" {
		parsedToken, err := authCtx.Auth.ParseToken(cookie)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		cookieExpiration = time.Unix(parsedToken.Payload.EXP, 0)
	} else if authCtx.AuthOptions.TokenDuration != 0 {
		cookieExpiration = time.Now().Add(authCtx.AuthOptions.TokenDuration)
	} else {
		// Defaults to 24 hours
		cookieExpiration = time.Now().Add(24 * time.Hour)
	}

	activeAccountCookie := &http.Cookie{
		Name:     globals.AuthActiveAccountCookie,
		Value:    activeBody.Address,
		Path:     "/",
		Expires:  cookieExpiration,
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

	return c.NoContent(http.StatusOK)
}
