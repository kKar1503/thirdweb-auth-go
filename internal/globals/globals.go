package globals

import "time"

const (
	AuthTokenCookiePrefix   = "thirdweb_auth_token"
	AuthActiveAccountCookie = "thirdweb_auth_active_account"
)

const (
	DefaultLoginPayloadDuration = 10 * time.Minute
	DefaultTokenDuration        = 24 * time.Hour
	DefaultRefreshInterval      = 5 * time.Second
)
