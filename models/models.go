package models

import "time"

type LoginInfo struct {
	Errmsg string
}

type ApiKeyData struct {
	Apikey      string
	Exists      bool
	ToDelete    bool
	CreatedDtTm time.Time
}
