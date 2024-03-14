package handlers

import (
	"net/http"
	"time"

	internalModels "github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/kKar1503/thirdweb-auth-go/models"
	"github.com/labstack/echo/v4"
)

func PayloadHandler(c echo.Context, authCtx *models.ThirdwebAuthContext) error {
	if c.Request().Method != "POST" {
		return c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "Invalid method. Only POST supported."})
	}

	payloadBody := &models.PayloadBody{}
	// TODO check on the omitempty binding
	if err := c.Bind(payloadBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Please provide an address"})
	}

	loginOtpions := &internalModels.LoginOptions{
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
