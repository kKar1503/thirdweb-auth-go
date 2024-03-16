package echo

import (
	"net/http"
	"time"

	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
	"github.com/kKar1503/thirdweb-auth-go/internal/auth"
	"github.com/kKar1503/thirdweb-auth-go/internal/helpers"

	"github.com/labstack/echo/v4"
)

func switchAccountHandler(c echo.Context, authCtx *auth.ThirdwebAuthContext) error {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	activeBody := &thirdwebauth.ActiveBody{}
	if err := c.Bind(activeBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Please provide an address"})
	}

	var cookieExpiration time.Time
	cookie := helpers.GetCookie(c.Request(), thirdwebauth.AuthTokenCookiePrefix+"_"+activeBody.Address)
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
		Name:     thirdwebauth.AuthActiveAccountCookie,
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
