package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	_ "embed"

	dataaccess "com.github.cork89/reddituf/db"
	"com.github.cork89/reddituf/models"
	argo "github.com/cork89/reddit-go"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var ddl string

var queries *dataaccess.Queries

func initDataaccess() error {
	ctx := context.Background()
	dbFile := "file:reddituf.db"
	// conn, err := sql.Open("sqlite3", ":memory:")
	conn, err := sql.Open("sqlite3", dbFile)

	if err != nil {
		return err
	}

	// create tables
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		return err
	}

	queries = dataaccess.New(conn)
	return nil
}

func translateDataAccessUser(user dataaccess.User) argo.User {
	return argo.User{
		UserCookie: argo.UserCookie{
			Username:          user.Username,
			RefreshExpireDtTm: user.RefreshExpireDtTm,
			AccessToken:       user.AccessToken,
			IconUrl:           user.IconUrl,
		},
		UserId:            int(user.ID),
		Subscribed:        user.Subscribed,
		SubscriptionDtTm:  "",
		RefreshToken:      user.RefreshToken,
		RemainingUploads:  int(user.RemainingUploads),
		UploadRefreshDtTm: user.UploadRefreshDtTm,
	}
}

func GetUser(username string) (argo.User, bool) {
	if username == "" {
		log.Printf("invalid user\n")
		return argo.User{}, false
	}

	user, err := queries.GetUserByUsername(context.Background(), username)

	if err != nil {
		log.Printf("failed to retrieve user by username, %s, err=%v\n", username, err)
		return argo.User{}, false
	}

	return translateDataAccessUser(user), true
}

func AddUser(user argo.User) bool {
	_, err := queries.CreateUser(context.Background(), dataaccess.CreateUserParams{
		Username:          user.Username,
		RefreshExpireDtTm: user.RefreshExpireDtTm,
		AccessToken:       user.AccessToken,
		IconUrl:           user.IconUrl,
		Subscribed:        user.Subscribed,
		SubscriptionDtTm:  time.Now(),
		RefreshToken:      user.RefreshToken,
		RemainingUploads:  int64(user.RemainingUploads),
		UploadRefreshDtTm: user.UploadRefreshDtTm,
	})
	if err != nil {
		log.Printf("failed to create user, %s, err=%v\n", user.Username, err)
		return false
	}
	return true
}

func UpdateUser(user argo.User) bool {
	_, err := queries.UpdateUser(context.Background(), dataaccess.UpdateUserParams{AccessToken: user.AccessToken, ID: int64(user.UserId), RefreshExpireDtTm: user.RefreshExpireDtTm})

	if err != nil {
		log.Printf("Failed to update user with username=%s, err=%v\n", user.Username, err)
		return false
	}
	return true
}

func DeleteUser(user argo.User) bool {
	err := queries.DeleteUser(context.Background(), int64(user.UserId))

	if err != nil {
		log.Printf("Failed to delete user with username=%s, err=%v\n", user.Username, err)
		return false
	}
	return true
}

func GetUserByApikey(apikey string) (argo.User, bool) {
	userId, err := queries.GetUserIdByApikey(context.Background(), hashApikey(apikey))

	if err != nil {
		log.Println("failed to retrieve user id from apikey")
		return argo.User{}, false
	}
	user, err := queries.GetUser(context.Background(), userId)
	if err != nil {
		log.Println("failed to retrieve user id from apikey")
		return argo.User{}, false
	}
	return translateDataAccessUser(user), true
}

func generateSecureRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

func hashApikey(apikey string) string {
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%s%s", apikey, ApikeySalt)))
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func CreateApiKey(user argo.User) (models.ApiKeyData, bool) {
	apikey, err := generateSecureRandomString(32)
	var apikeyData models.ApiKeyData
	if err != nil {
		log.Printf("failed to create apikey for user=%s\n", user.Username)
		return apikeyData, false
	}
	hashHex := hashApikey(apikey)
	now := time.Now().UTC()

	_, err = queries.CreateApiKey(context.Background(), dataaccess.CreateApiKeyParams{
		UserID:      int64(user.UserId),
		Apikey:      hashHex,
		CreatedDtTm: now,
	})

	if err != nil {
		log.Printf("failed to create apikey for user=%s, err=%v\n", user.Username, err)
		return apikeyData, false
	}
	apikeyData.Apikey = apikey
	apikeyData.Exists = true
	apikeyData.CreatedDtTm = now

	return apikeyData, true
}

func UpdateApiKey(user argo.User) (models.ApiKeyData, bool) {
	apikey, err := generateSecureRandomString(32)
	var apikeyData models.ApiKeyData

	if err != nil {
		log.Printf("failed to create apikey for user=%s\n", user.Username)
		return apikeyData, false
	}
	hashHex := hashApikey(apikey)
	now := time.Now().UTC()

	_, err = queries.UpdateApiKey(context.Background(), dataaccess.UpdateApiKeyParams{
		UserID:      int64(user.UserId),
		Apikey:      hashHex,
		CreatedDtTm: now,
	})

	if err != nil {
		log.Printf("failed to update apikey for user=%s, err=%v\n", user.Username, err)
		return apikeyData, false
	}
	apikeyData.Apikey = apikey
	apikeyData.Exists = true
	apikeyData.CreatedDtTm = now

	return apikeyData, true
}

func ApikeyExists(user argo.User) models.ApiKeyData {
	apikeyRow, err := queries.GetApikeyByUserId(context.Background(), int64(user.UserId))
	if err != nil {
		return models.ApiKeyData{
			Exists: false,
		}
	}
	return models.ApiKeyData{
		Exists:      true,
		CreatedDtTm: apikeyRow.CreatedDtTm,
	}
}

func DeleteApiKey(userId int) bool {
	err := queries.DeleteApiKey(context.Background(), int64(userId))
	return err == nil
}

func GetOrCreateRatelimit(userId int) (dataaccess.Ratelimit, bool) {
	ratelimit, err := queries.GetRatelimitByUserID(context.Background(), int64(userId))
	if err != nil {
		if err == sql.ErrNoRows {
			// Create new ratelimit entry if not found
			newRatelimit, createErr := queries.CreateRatelimit(context.Background(), dataaccess.CreateRatelimitParams{
				UserID:            int64(userId),
				LastCallTimestamp: time.Now().UTC(),
				CallCount:         1,
			})
			if createErr != nil {
				log.Printf("failed to create ratelimit for user %d: %v\n", userId, createErr)
				return dataaccess.Ratelimit{}, false
			}
			return newRatelimit, true
		}
		log.Printf("failed to get ratelimit for user %d: %v\n", userId, err)
		return dataaccess.Ratelimit{}, false
	}
	return ratelimit, true
}

func IncrementRatelimit(ratelimit dataaccess.Ratelimit) bool {
	_, err := queries.UpdateRatelimit(context.Background(), dataaccess.UpdateRatelimitParams{
		UserID:            ratelimit.UserID,
		LastCallTimestamp: time.Now().UTC(),
		CallCount:         ratelimit.CallCount + 1,
	})
	if err != nil {
		log.Printf("failed to increment ratelimit for user %d: %v\n", ratelimit.UserID, err)
		return false
	}
	return true
}

func ResetRatelimit(ratelimit dataaccess.Ratelimit) bool {
	_, err := queries.UpdateRatelimit(context.Background(), dataaccess.UpdateRatelimitParams{
		UserID:            ratelimit.UserID,
		LastCallTimestamp: time.Now().UTC(),
		CallCount:         1,
	})
	if err != nil {
		log.Printf("failed to reset ratelimit for user %d: %v\n", ratelimit.UserID, err)
		return false
	}
	return true
}
