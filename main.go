package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	models "com.github.cork89/reddituf/models"
	"com.github.cork89/reddituf/templates"
	"github.com/a-h/templ"
	argo "github.com/cork89/reddit-go"
	"github.com/joho/godotenv"
)

var RedditAuthUrl string
var ArgoClient argo.RedditClient

const APIKEY_COOKIE string = "apikey_cookie"

func apikeyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCtx := ctx.Value(SessionCtx)
	var user argo.User
	var ok bool
	if userCtx != nil {
		user = userCtx.(argo.User)
		ok = true
	} else {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	if !ok {
		http.Error(w, "No user found for api key", http.StatusNotFound)
		return
	}

	apikeyData := ApikeyExists(user)
	if apikeyData.Exists {
		ok := DeleteApiKey(user.UserId)
		if !ok {
			log.Printf("failed to delete api key, for user=%s\n", user.Username)
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func apikeyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCtx := ctx.Value(SessionCtx)
	var user argo.User
	var ok bool
	if userCtx != nil {
		user = userCtx.(argo.User)
		ok = true
	} else {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	if !ok {
		http.Error(w, "No user found for api key", http.StatusNotFound)
		return
	}

	apikeyData := ApikeyExists(user)
	if apikeyData.Exists {
		apikeyData, ok = UpdateApiKey(user)
	} else {
		apikeyData, ok = CreateApiKey(user)
	}

	if !ok {
		http.Error(w, "failed to create api key", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: APIKEY_COOKIE, Value: apikeyData.Apikey, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{Name: argo.CookieName, Value: "", Path: "/", Expires: time.Unix(0, 0), HttpOnly: true}
	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusFound)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, RedditAuthUrl, http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	queryParams := r.URL.Query()

	state := queryParams.Get("state")
	code := queryParams.Get("code")

	cookieVal := r.Context().Value(SessionCtx)
	if cookieVal == nil {
		loginInfo := models.LoginInfo{}

		if state == "" || code == "" {
			login := templates.Login(loginInfo)
			if err := login.Render(context.Background(), w); err != nil {
				log.Printf("loginHandler state/code err: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		loginInfo.Errmsg = "Sorry something went wrong :("
		login := templates.Login(loginInfo)

		accessToken, ok := ArgoClient.GetRedditAccessToken(state, code)

		log.Printf("access token=%v\n", accessToken)
		if !ok {
			if err := login.Render(context.Background(), w); err != nil {
				log.Printf("loginHandler accesstoken err: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			log.Printf("failed to retrieve reddit access token for state=%s, code=%s\n", state, code)
			return
		}
		userData, ok := ArgoClient.GetUserData(*accessToken)
		if !ok {
			log.Println("failed to retrieve user data")
			if err := login.Render(context.Background(), w); err != nil {
				log.Printf("getUserData err: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)

			}
			return
		} else {
			log.Println(userData)
			_, ok = GetUser(userData.Username)
			if !ok {
				userAdded := AddUser(userData)
				if !userAdded {
					if err := login.Render(context.Background(), w); err != nil {
						log.Printf("loginHandler adduser err: %v", err)
						http.Error(w, err.Error(), http.StatusInternalServerError)

					}
					return
				}
			}
		}
		cookie := ArgoClient.CreateUserCookie(userData.UserCookie)
		http.SetCookie(w, &cookie)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

type UnfurlData struct {
	Link string `json:"link"`
	Msg  string `json:"msg"`
}

func unfurlHandler(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()

	subreddit := queryParams.Get("subreddit")
	shortLink := queryParams.Get("shortLink")

	authorization := r.Header.Get("Authorization")
	authParts := strings.Split(authorization, " ")
	if !(len(authParts) == 2 && authParts[0] == "Bearer" && authParts[1] != "") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, ok := GetUserByApikey(authParts[1])

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	unfurledLink := ArgoClient.UnfurlRedditLink(subreddit, shortLink, user)

	body := UnfurlData{Link: unfurledLink.Link}

	switch unfurledLink.StatusCode {
	case 500:
		body.Msg = "Failed to unfurl reddit link"
	case 401:
		body.Msg = "Not Authorized"
	case 429:
		body.Msg = "Too Many Requests"
	}

	bytes, err := json.Marshal(body)

	if err != nil {
		log.Println("failed to marshal verify response, err: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if unfurledLink.StatusCode >= 400 {
		w.WriteHeader(unfurledLink.StatusCode)
	}
	w.Header().Set("Content-Type", "application/json")
	// Currently ratelimit headers not being set from reddit, will likely need to implement our own
	// w.Header().Set("x-ratelimit-remaining", unfurledLink.RatelimitRemaining)
	// w.Header().Set("x-ratelimit-reset", unfurledLink.RatelimitReset)
	// w.Header().Set("x-ratelimit-used", unfurledLink.RatelimitUsed)
	w.Write(bytes)
}

func settingsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCtx := ctx.Value(SessionCtx)

	var user argo.User
	if userCtx != nil {
		user = userCtx.(argo.User)
	} else {
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	ok := DeleteApiKey(user.UserId)

	if !ok {
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	ok = DeleteUser(user)

	if !ok {
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	c := &http.Cookie{Name: argo.CookieName, Value: "", Path: "/", Expires: time.Unix(0, 0), HttpOnly: true}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/", http.StatusFound)

}

func settingsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCtx := ctx.Value(SessionCtx)

	queryParams := r.URL.Query()
	action := queryParams.Get("action")

	if userCtx == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	user := userCtx.(argo.User)
	settings := templates.Settings(&user, action == "delete-account")
	err := settings.Render(context.Background(), w)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userCtx := ctx.Value(SessionCtx)
	cookie, err := r.Cookie(APIKEY_COOKIE)

	queryParams := r.URL.Query()
	action := queryParams.Get("action")

	apikeyData := models.ApiKeyData{Exists: false}
	var apikey string
	if err == nil {
		apikey = cookie.Value
		c := &http.Cookie{Name: APIKEY_COOKIE, Value: "", Path: "/", Expires: time.Unix(0, 0), HttpOnly: true}
		http.SetCookie(w, c)
	}
	var index templ.Component

	if userCtx != nil {
		user := userCtx.(argo.User)
		apikeyData = ApikeyExists(user)
		apikeyData.Apikey = apikey
		apikeyData.ToDelete = action == "delete-api-key"
		index = templates.Index(&user, apikeyData)
	} else {
		index = templates.Index(nil, apikeyData)
	}

	err = index.Render(context.Background(), w)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

var ApikeySalt string

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalln("failed to load .env")
	}
	initDataaccess()

	redditOAuthState := os.Getenv("REDDIT_OAUTH_STATE")
	redditRedirectUri := os.Getenv("REDDIT_REDIRECT_URI")
	redditClientId := os.Getenv("REDDIT_CLIENT_ID")
	ApikeySalt = os.Getenv("APIKEY_SALT")

	clientEnvs := argo.ClientEnvs{
		JwtSecret:  os.Getenv("REDDIT_JWT_SECRET"),
		OauthState: redditOAuthState,
		BasicAuth: func() string {
			auth := fmt.Sprintf("%s:%s", redditClientId, os.Getenv("REDDIT_SECRET"))
			return base64.StdEncoding.EncodeToString([]byte(auth))
		}(),
		RedirectUri: redditRedirectUri,
	}
	ArgoClient = argo.RedditClient{}
	ArgoClient.New(clientEnvs)

	RedditAuthUrl = fmt.Sprintf("https://www.reddit.com/api/v1/authorize?client_id=%s&response_type=code&state=%s&redirect_uri=%s&duration=permanent&scope=read,identity",
		redditClientId, redditOAuthState, redditRedirectUri)

	router := http.NewServeMux()
	router.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.HandleFunc("POST /settings/delete/", settingsDeleteHandler)
	router.HandleFunc("GET /settings/", settingsHandler)
	router.HandleFunc("POST /apikey/delete/", apikeyDeleteHandler)
	router.HandleFunc("POST /apikey/", apikeyHandler)
	router.HandleFunc("GET /logout/", logoutHandler)
	router.HandleFunc("POST /login/", loginPostHandler)
	router.HandleFunc("GET /login/", loginHandler)
	router.HandleFunc("GET /unfurl/", unfurlHandler)
	router.HandleFunc("GET /", homeHandler)

	stack := CreateStack(
		Logging,
		IsLoggedIn,
	)

	server := http.Server{
		Addr:    ":8090",
		Handler: stack(router),
	}
	server.ListenAndServe()
}
