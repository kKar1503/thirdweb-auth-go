package echo

import (
	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
	"github.com/kKar1503/thirdweb-auth-go/internal/auth"
	"github.com/kKar1503/thirdweb-auth-go/internal/helpers"

	"github.com/labstack/echo/v4"
)

var thirdwebAuthCtx *auth.ThirdwebAuthContext

func InitThirdwebAuth(
	group *echo.Group,
	config *thirdwebauth.ThirdwebAuthConfig,
) {
	thirdwebAuthCtx = &auth.ThirdwebAuthContext{
		Auth:                auth.NewThirdwebAuth(config.Domain, config.Verifier).WithOptions(config.ThirdwebAuthOptions),
		AuthOptions:         config.AuthOptions,
		CookieOptions:       config.CookieOptions,
		Callbacks:           config.Callbacks,
		ThirdwebAuthOptions: config.ThirdwebAuthOptions,
	}
}

func GetUser(c echo.Context) (*thirdwebauth.ThirdwebAuthUser, error) {
	return helpers.GetUser(c.Request(), thirdwebAuthCtx)
}

func AttachRoutesToGroup(group *echo.Group) {
	group.POST("/login", func(c echo.Context) error {
		return loginHandler(c, thirdwebAuthCtx)
	})
	group.POST("/logout", func(c echo.Context) error {
		return logoutHandler(c, thirdwebAuthCtx)
	})
	group.GET("/user", func(c echo.Context) error {
		return userHandler(c, thirdwebAuthCtx)
	})
	group.POST("/payload", func(c echo.Context) error {
		return payloadHandler(c, thirdwebAuthCtx)
	})
	group.POST("/switch-account", func(c echo.Context) error {
		return switchAccountHandler(c, thirdwebAuthCtx)
	})
}
