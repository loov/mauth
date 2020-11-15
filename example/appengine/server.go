package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/providers/google"

	"loov.dev/mauth"
)

const SessionName = "user"

type Config struct {
	Host       string
	UserSecret string
	AuthSecret string

	Credentials Credentials
}

type Server struct {
	log    *log.Logger
	auth   *mauth.Sessions
	state  sessions.Store
	config Config
}

func NewServer(log *log.Logger, config Config) *Server {
	server := &Server{
		log:    log,
		config: config,
	}

	state := sessions.NewCookieStore(secretWithFallback(config.UserSecret))
	state.Options.HttpOnly = true
	state.Options.Secure = true
	server.state = state

	cred := config.Credentials
	server.auth = mauth.NewWithCookieStore(secretWithFallback(config.AuthSecret), mauth.Providers{
		"google": google.New(cred.ClientID, cred.ClientSecret, cred.RedirectURIs[0], "profile", "openid", "email"),
	})

	return server
}

func (server *Server) Register(router *mux.Router) {
	router.HandleFunc("/", server.Dashboard)
	router.HandleFunc("/auth/logout", server.Logout)
	router.HandleFunc("/auth/{provider}/login", server.RedirectToLogin)
	router.HandleFunc("/auth/{provider}/callback", server.Callback)
}

func (server *Server) Dashboard(w http.ResponseWriter, r *http.Request) {
	sess, _ := server.state.New(r, SessionName)
	flashes := sess.Flashes()

	var user *mauth.User
	if v, ok := sess.Values["user"]; ok {
		if u, ok := v.(mauth.User); ok {
			user = &u
		} else {
			delete(sess.Values, "user")
			flashes = append(flashes, fmt.Sprintf("invalid user type %T", v))
			sess.Save(r, w)
		}
	}

	err := dashboardTemplate.Execute(w, map[string]interface{}{
		"Flashes": flashes,
		"User":    user,
	})
	if err != nil {
		server.log.Printf("failed to display template: %+v", err)
	}
}

func (server *Server) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	providerName := mux.Vars(r)["provider"]
	user, err := server.auth.FinishLogin(providerName, w, r)
	if err == nil {
		sess, _ := server.state.New(r, SessionName)
		sess.AddFlash("already logged in")
		sess.Values["user"] = user
		err := sess.Save(r, w)
		if err != nil {
			server.log.Printf("unable to add user to cookie: %v", err)
		}

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	url, err := server.auth.BeginLogin(providerName, w, r)
	if err != nil {
		sess, _ := server.state.New(r, SessionName)
		sess.AddFlash(err.Error())
		sess.Save(r, w)

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (server *Server) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := mux.Vars(r)["provider"]
	user, err := server.auth.FinishLogin(providerName, w, r)
	if err != nil {
		sess, _ := server.state.New(r, SessionName)
		sess.AddFlash("failed to login: " + err.Error())
		err := sess.Save(r, w)
		if err != nil {
			server.log.Printf("unable to add flash: %v", err)
		}
	} else {
		sess, _ := server.state.New(r, SessionName)
		sess.Values["user"] = user
		err := sess.Save(r, w)
		if err != nil {
			server.log.Printf("unable to add user to cookie: %v", err)
		}
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (server *Server) Logout(w http.ResponseWriter, r *http.Request) {
	err := server.auth.Logout(w, r)
	if err != nil {
		server.log.Println(err)
	}

	if sess, err := server.state.Get(r, SessionName); err == nil {
		sess.Options.MaxAge = -1
		sess.Values = make(map[interface{}]interface{})
		if err := sess.Save(r, w); err != nil {
			server.log.Println(err)
		}
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

var dashboardTemplate = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html class="no-js">
<head>
	<meta charset="utf-8">
	<title>mauth</title>
</head>
<body>
	<div>
	{{ range $flash := .Flashes }}
	<p style="background: #fee;">{{ $flash }}</p>
	{{ end }}
	</div>

	<h2>User</h2>
	{{ with .User }}
	<div>
		<p><a href="/auth/logout">Logout</a></p>
		<p>Name: {{.Name}}</p>
		<p>Email: {{.Email}}</p>
		<p>UserID: {{.UserID}}</p>
		<p>ExpiresAt: {{.ExpiresAt}}</p>
	</div>
	{{ else }}
	<p>User not logged in.</p>
	{{ end }}

	<h2>Login</h2>
	<div>
	<p><a href="/auth/google/login">Google</a></p>
	</div>
</body>
</html>
`))
