package thirdwebauth

type VerifyOptions struct {
	Domain        string             `json:"domain,omitempty"`
	Statement     string             `json:"statement,omitempty"`
	URI           string             `json:"uri,omitempty"`
	Version       string             `json:"version,omitempty"`
	ChainID       string             `json:"chainId,omitempty"`
	Resources     []string           `json:"resources,omitempty"`
	ValidateNonce func(string) error `json:"-"`
}
