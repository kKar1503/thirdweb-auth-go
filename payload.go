package thirdwebauth

import (
	"net/http"
	"time"

	"github.com/kKar1503/thirdweb-auth-go/internal/auth"
	"github.com/kKar1503/thirdweb-auth-go/internal/models"
	"github.com/labstack/echo/v4"
)

type PayloadBody struct {
	Address string `json:"address"`
	ChainID string `json:"chainId,omitempty"`
}

type ActiveBody struct {
	Address string `json:"address"`
}

type LoginPayloadBody struct {
	Payload models.LoginPayload `json:"payload"`
}

type ThirdwebAuthUser struct {
	Address string      `json:"address"`
	Session interface{} `json:"session,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ThirdwebAuthConfig struct {
	Domain              string
	Verifier            SignVerifier
	AuthOptions         ThirdwebAuthConfigAuthOptions
	CookieOptions       ThirdwebAuthConfigCookieOptions
	Callbacks           ThirdwebAuthConfigCallbacks
	ThirdwebAuthOptions models.ThirdwebAuthOptions
}

type ThirdwebAuthContext struct {
	Auth                *auth.ThirdwebAuth
	AuthOptions         ThirdwebAuthConfigAuthOptions
	CookieOptions       ThirdwebAuthConfigCookieOptions
	Callbacks           ThirdwebAuthConfigCallbacks
	ThirdwebAuthOptions models.ThirdwebAuthOptions
}

type ThirdwebAuthConfigAuthOptions struct {
	Statement            string             `json:"statement,omitempty"`
	URI                  string             `json:"uri,omitempty"`
	Version              string             `json:"version,omitempty"`
	ChainID              string             `json:"chainId,omitempty"`
	Resources            []string           `json:"resources,omitempty"`
	ValidateNonce        func(string) error `json:"-"`
	ValidateTokenId      func(string) error `json:"-"`
	LoginPayloadDuration time.Duration      `json:"loginPayloadDuration,omitempty"`
	TokenDuration        time.Duration      `json:"tokenDuration,omitempty"`
	RefreshInterval      time.Duration      `json:"refreshInterval,omitempty"`
}

type ThirdwebAuthConfigCookieOptions struct {
	Domain   *string        `json:"domain,omitempty"`
	Path     *string        `json:"path,omitempty"`
	SameSite *http.SameSite `json:"sameSite,omitempty"`
	Secure   *bool          `json:"secure,omitempty"`
}

type ThirdwebAuthConfigCallbacks struct {
	OnLogin  func(echo.Context, string) interface{}
	OnToken  func(echo.Context, string) interface{}
	OnUser   func(echo.Context, *models.User) interface{}
	OnLogout func(echo.Context, *models.User)
}
