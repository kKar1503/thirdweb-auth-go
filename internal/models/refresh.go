package models

import (
	"time"

	"github.com/kKar1503/thirdweb-auth-go/internal/globals"
)

type RefreshOptions struct {
	ExpirationTime time.Time `json:"expirationTime"`
}

func DefaultRefreshOptions() *RefreshOptions {
	return &RefreshOptions{ExpirationTime: time.Now().UTC().Add(globals.DefaultTokenDuration)}
}
