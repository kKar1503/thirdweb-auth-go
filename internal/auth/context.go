package auth

import thirdwebauth "github.com/kKar1503/thirdweb-auth-go"

type ThirdwebAuthContext struct {
	Auth                *ThirdwebAuth
	AuthOptions         thirdwebauth.ThirdwebAuthConfigAuthOptions
	CookieOptions       thirdwebauth.ThirdwebAuthConfigCookieOptions
	Callbacks           thirdwebauth.ThirdwebAuthConfigCallbacks
	ThirdwebAuthOptions thirdwebauth.ThirdwebAuthOptions
}
