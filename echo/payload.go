package echo

import (
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	thirdwebauth "github.com/kKar1503/thirdweb-auth-go"
	"github.com/kKar1503/thirdweb-auth-go/internal/auth"

	"github.com/labstack/echo/v4"
)

func payloadHandler(c echo.Context, authCtx *auth.ThirdwebAuthContext) error {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	payloadBody := &thirdwebauth.PayloadBody{}
	if err := c.Bind(payloadBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Please provide an address"})
	}

	if err := validator.New().Struct(payloadBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Please provide an address"})
	}

	loginOtpions := &thirdwebauth.LoginOptions{
		Address:   payloadBody.Address,
		Statement: authCtx.AuthOptions.Statement,
		URI:       authCtx.AuthOptions.URI,
		Version:   authCtx.AuthOptions.Version,
		ChainID:   authCtx.AuthOptions.ChainID,
		Resources: authCtx.AuthOptions.Resources,
	}
	if payloadBody.ChainID != "" {
		loginOtpions.ChainID = payloadBody.ChainID
	}
	if authCtx.AuthOptions.LoginPayloadDuration != 0 {
		loginOtpions.ExpirationTime = time.Now().Add(authCtx.AuthOptions.LoginPayloadDuration)
	}

	loginPayload := authCtx.Auth.Payload(loginOtpions)

	return c.JSON(http.StatusOK, map[string]interface{}{"payload": loginPayload})
}
