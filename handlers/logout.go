package handlers

import (
	"net/http"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/helpers"
	internalModels "github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

func LogoutHandler(c echo.Context, authCtx *models.ThirdwebAuthContext) error {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	activeCookie := helpers.GetActiveCookie(c)
	if activeCookie == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No logged in user to logout."})
	}

	if authCtx.Callbacks.OnLogout != nil {
		user, err := helpers.GetUser(c, authCtx)
		if err != nil {
			return c.JSON(
				http.StatusInternalServerError,
				map[string]string{"error": "Failed to get user from request due to: " + err.Error()},
			)
		}
		authCtx.Callbacks.OnLogout(c, &internalModels.User{
			Address: user.Address,
			Session: user.Session,
		})
	}

	cookie := &http.Cookie{
		Name:     activeCookie,
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(5 * time.Second),
		HttpOnly: true,
		Secure:   true,
	}
	if authCtx.CookieOptions.Domain != nil {
		cookie.Domain = *authCtx.CookieOptions.Domain
	}
	if authCtx.CookieOptions.Path != nil {
		cookie.Path = *authCtx.CookieOptions.Path
	}
	if authCtx.CookieOptions.SameSite != nil {
		cookie.SameSite = *authCtx.CookieOptions.SameSite
	}
	if authCtx.CookieOptions.Secure != nil {
		cookie.Secure = *authCtx.CookieOptions.Secure
	}
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, map[string]string{"message": "Successfully logged out"})
}
