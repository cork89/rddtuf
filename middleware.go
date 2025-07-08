package main

import (
	"context"
	"log"
	"net/http"
	"time"
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
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), SessionCtx, username)
		r = r.Clone(ctx)

		next.ServeHTTP(w, r)
	})
}
