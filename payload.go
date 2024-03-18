package thirdwebauth

import (
	"net/http"
	"time"
)

type PayloadBody struct {
	Address string `json:"address"           validate:"required"`
	ChainID string `json:"chainId,omitempty"`
}

type ActiveBody struct {
	Address string `json:"address" validate:"required"`
}

type LoginPayloadBody struct {
	Payload LoginPayload `json:"payload" validate:"required"`
}

type ThirdwebAuthUser struct {
	Address string      `json:"address"           validate:"required"`
	Session interface{} `json:"session,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ThirdwebAuthConfig struct {
	Domain              string
	Verifier            SignVerifier
	AuthOptions         ThirdwebAuthConfigAuthOptions
	CookieOptions       ThirdwebAuthConfigCookieOptions
	Callbacks           ThirdwebAuthConfigCallbacks
	ThirdwebAuthOptions ThirdwebAuthOptions
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
	OnLogin  func(*http.Request, string) interface{}
	OnToken  func(*http.Request, string) interface{}
	OnUser   func(*http.Request, *User) interface{}
	OnLogout func(*http.Request, *User)
}
