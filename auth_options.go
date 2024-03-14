package thirdwebauth

type ThirdwebAuthOptions struct {
	JwtISS       string
	ClientID     string
	ClientSecret string
}

func NewThirdwebAuthOptions() *ThirdwebAuthOptions {
	return &ThirdwebAuthOptions{}
}

func (o *ThirdwebAuthOptions) WithClientID(clientID string) *ThirdwebAuthOptions {
	o.ClientID = clientID
	return o
}

func (o *ThirdwebAuthOptions) WithClientSecret(clientSecret string) *ThirdwebAuthOptions {
	o.ClientSecret = clientSecret
	return o
}

func (o *ThirdwebAuthOptions) WithJwtISS(jwtISS string) *ThirdwebAuthOptions {
	o.JwtISS = jwtISS
	return o
}
