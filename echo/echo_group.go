package echo

import (
	"github.com/kKar1503/thirdweb-auth-go/handlers"
	"github.com/kKar1503/thirdweb-auth-go/helpers"
	"github.com/kKar1503/thirdweb-auth-go/internal/auth"
	"github.com/kKar1503/thirdweb-auth-go/models"

	"github.com/labstack/echo/v4"
)

var thirdwebAuthCtx *models.ThirdwebAuthContext

func InitThirdwebAuth(
	group *echo.Group,
	config *models.ThirdwebAuthConfig,
) {
	thirdwebAuthCtx = &models.ThirdwebAuthContext{
		Auth:                auth.NewThirdwebAuth(config.Domain, config.Verifier).WithOptions(config.ThirdwebAuthOptions),
		AuthOptions:         config.AuthOptions,
		CookieOptions:       config.CookieOptions,
		Callbacks:           config.Callbacks,
		ThirdwebAuthOptions: config.ThirdwebAuthOptions,
	}
}

func GetUser(c echo.Context) (*models.ThirdwebAuthUser, error) {
	return helpers.GetUser(c, thirdwebAuthCtx)
}

func AttachRoutesToGroup(group *echo.Group) {
	group.POST("/login", func(c echo.Context) error {
		return handlers.LoginHandler(c, thirdwebAuthCtx)
	})
	group.POST("/logout", func(c echo.Context) error {
		return handlers.LogoutHandler(c, thirdwebAuthCtx)
	})
	group.GET("/user", func(c echo.Context) error {
		return handlers.UserHandler(c, thirdwebAuthCtx)
	})
	group.POST("/payload", func(c echo.Context) error {
		return handlers.PayloadHandler(c, thirdwebAuthCtx)
	})
	group.POST("/switch-account", func(c echo.Context) error {
		return handlers.SwitchAccountHandler(c, thirdwebAuthCtx)
	})
}
