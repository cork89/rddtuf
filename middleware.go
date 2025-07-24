package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	redditgo "github.com/cork89/reddit-go"
)

type HttpContext string

const (
	SessionCtx HttpContext = "SessionCtx"
	ApikeyCtx  HttpContext = "ApikeyCtx"
)

type Middleware func(http.Handler) http.Handler

func CreateStack(mw ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			next = mw[i](next)
		}
		return next
	}
}

type scWriter struct {
	http.ResponseWriter
	statusCode int
}

func (mw *scWriter) WriteHeader(statusCode int) {
	mw.ResponseWriter.WriteHeader(statusCode)
	mw.statusCode = statusCode
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		opWriter := &scWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(opWriter, r)
		log.Println(opWriter.statusCode, r.Method, r.URL.Path, time.Since(start))
	})
}

func IsLoggedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, ok := ArgoClient.GetUserCookie(r)

		authorization := r.Header.Get("Authorization")
		authParts := strings.Split(authorization, " ")

		notAuthed := !(len(authParts) == 2 && authParts[0] == "Bearer" && authParts[1] != "")

		if notAuthed && !ok {
			next.ServeHTTP(w, r)
			return
		}

		var user redditgo.User
		if !ok {
			user, ok = GetUserByApikey(authParts[1])
		} else {
			user, ok = GetUser(username)
		}

		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if user.RefreshExpireDtTm.Before(time.Now()) {
			usr, ok := ArgoClient.RefreshRedditAccessToken(&user)

			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			ok = UpdateUser(*usr)
			if ok {
				user = *usr
			}
		}

		if ok {
			ctx := context.WithValue(r.Context(), SessionCtx, user)
			r = r.Clone(ctx)
		}
		next.ServeHTTP(w, r)

	})
}

func RateLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userCtx := r.Context().Value(SessionCtx)
		if userCtx == nil {
			next.ServeHTTP(w, r)
			return
		}

		user := userCtx.(redditgo.User)
		ratelimit, ok := GetOrCreateRatelimit(user.UserId)
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		rateLimit := 10
		if user.Subscribed {
			rateLimit = 100
		}

		if now.Minute() != ratelimit.LastCallTimestamp.Minute() || now.Day() != ratelimit.LastCallTimestamp.Day() {
			ResetRatelimit(ratelimit)
			ratelimit.CallCount = 1
		} else {
			if int(ratelimit.CallCount) >= rateLimit {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			IncrementRatelimit(ratelimit)
		}

		w.Header().Set("x-ratelimit-remaining", fmt.Sprintf("%d", rateLimit-int(ratelimit.CallCount)))
		w.Header().Set("x-ratelimit-used", fmt.Sprintf("%d", ratelimit.CallCount))
		nextMinute := now.Truncate(time.Minute).Add(time.Minute)
		resetInSeconds := int(nextMinute.Sub(now).Seconds())
		w.Header().Set("x-ratelimit-reset", fmt.Sprintf("%d", resetInSeconds))

		next.ServeHTTP(w, r)
	})
}
