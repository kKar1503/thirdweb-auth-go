package helpers

import (
	"errors"
	"net/http"
	"strings"

	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
	"github.com/kKar1503/thirdweb-auth-go/internal/auth"
)

var TokenNotFoundErr = errors.New("token not found")

func GetCookie(req *http.Request, cookieName string) string {
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

func GetActiveCookie(req *http.Request) string {
	if len(req.Cookies()) == 0 {
		return ""
	}

	activeAccount := GetCookie(req, thirdwebauth.AuthActiveAccountCookie)
	if activeAccount != "" {
		return thirdwebauth.AuthTokenCookiePrefix + "_" + activeAccount
	}

	return thirdwebauth.AuthTokenCookiePrefix
}

func GetToken(req *http.Request) string {
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		authHeaderSplit := strings.Split(authHeader, " ")
		if len(authHeaderSplit) == 2 {
			return authHeaderSplit[1]
		}
	}

	if len(req.Cookies()) == 0 {
		return ""
	}

	activeCookie := GetActiveCookie(req)
	if activeCookie != "" {
		return ""
	}

	return GetCookie(req, activeCookie)
}

func GetUser(req *http.Request, authCtx *auth.ThirdwebAuthContext) (*thirdwebauth.ThirdwebAuthUser, error) {
	token := GetToken(req)
	if token == "" {
		return nil, nil // null user
	}

	user, err := authCtx.Auth.Authenticate(token, &thirdwebauth.AuthenticateOptions{
		ValidateTokenId: func(tokenId string) error {
			return authCtx.AuthOptions.ValidateTokenId(tokenId)
		},
	})
	if err != nil {
		return nil, nil // null user
	}

	thirdwebAuthUser := &thirdwebauth.ThirdwebAuthUser{
		Address: user.Address,
		Session: user.Session,
	}

	if authCtx.Callbacks.OnUser == nil {
		return thirdwebAuthUser, nil
	}

	data := authCtx.Callbacks.OnUser(req, user)
	if data != nil {
		thirdwebAuthUser.Data = data
	}

	return thirdwebAuthUser, nil
}
