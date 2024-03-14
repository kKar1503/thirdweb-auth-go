package thirdwebauth

import "time"

type RefreshOptions struct {
	ExpirationTime time.Time `json:"expirationTime"`
}

func DefaultRefreshOptions() *RefreshOptions {
	return &RefreshOptions{ExpirationTime: time.Now().UTC().Add(DefaultTokenDuration)}
}
