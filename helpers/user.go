package helpers

import (
	"errors"
	"strings"

	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
	internalModels "github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

var TokenNotFoundErr = errors.New("token not found")

func GetCookie(c echo.Context, cookieName string) string {
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

func GetActiveCookie(c echo.Context) string {
	if len(c.Cookies()) == 0 {
		return ""
	}

	activeAccount := GetCookie(c, globals.AuthActiveAccountCookie)
	if activeAccount != "" {
		return globals.AuthTokenCookiePrefix + "_" + activeAccount
	}

	return globals.AuthTokenCookiePrefix
}

func GetToken(c echo.Context) string {
	if authHeader := c.Request().Header.Get("Authorization"); authHeader != "" {
		authHeaderSplit := strings.Split(authHeader, " ")
		if len(authHeaderSplit) == 2 {
			return authHeaderSplit[1]
		}
	}

	if len(c.Cookies()) == 0 {
		return ""
	}

	activeCookie := GetActiveCookie(c)
	if activeCookie != "" {
		return ""
	}

	return GetCookie(c, activeCookie)
}

func GetUser(c echo.Context, authCtx *models.ThirdwebAuthContext) (*models.ThirdwebAuthUser, error) {
	token := GetToken(c)
	if token == "" {
		return nil, nil // null user
	}

	user, err := authCtx.Auth.Authenticate(token, &internalModels.AuthenticateOptions{
		ValidateTokenId: func(tokenId string) error {
			return authCtx.AuthOptions.ValidateTokenId(tokenId)
		},
	})
	if err != nil {
		return nil, nil // null user
	}

	thirdwebAuthUser := &models.ThirdwebAuthUser{
		Address: user.Address,
		Session: user.Session,
	}

	if authCtx.Callbacks.OnUser == nil {
		return thirdwebAuthUser, nil
	}

	data := authCtx.Callbacks.OnUser(c, user)
	if data != nil {
		thirdwebAuthUser.Data = data
	}

	return thirdwebAuthUser, nil
}
