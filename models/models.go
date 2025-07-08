package models

import "time"

type LoginInfo struct {
	Errmsg string
}

type ApiKeyData struct {
	Apikey      string
	Exists      bool
	CreatedDtTm time.Time
}
