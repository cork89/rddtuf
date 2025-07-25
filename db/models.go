// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package db

import (
	"time"
)

type Apikey struct {
	ID          int64
	UserID      int64
	Apikey      string
	CreatedDtTm time.Time
}

type Ratelimit struct {
	ID                int64
	UserID            int64
	LastCallTimestamp time.Time
	CallCount         int64
}

type User struct {
	ID                int64
	Username          string
	RefreshToken      string
	RefreshExpireDtTm time.Time
	AccessToken       string
	IconUrl           string
	Subscribed        bool
	SubscriptionDtTm  time.Time
	RemainingUploads  int64
	UploadRefreshDtTm time.Time
}
