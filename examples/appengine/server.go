package main

import (
	"encoding/gob"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/providers/google"

	"loov.dev/mauth"
)

// SessionName is the default session name for a logged in user.
const SessionName = "user"

// Config defines options for the Server.
type Config struct {
	Host       string
	UserSecret string
	AuthSecret string

	Credentials Credentials
}

// Server manages login/logout with user sessions.
type Server struct {
	log    *log.Logger
	auth   *mauth.Sessions
	state  sessions.Store
	config Config
}

// User is the information we keep about the user.
type User struct {
	Name      string
	Email     string
	UserID    string
	AvatarURL string
}

func init() { gob.Register(User{}) }

// NewServer creates a new server.
func NewServer(log *log.Logger, config Config) *Server {
	server := &Server{
		log:    log,
		config: config,
	}

	// state is used to manage user sessions
	state := sessions.NewCookieStore(secretWithFallback(config.UserSecret))
	state.Options.HttpOnly = true
	state.Options.Secure = true
	server.state = state

	// auth is used to manage authentication workflows
	cred := config.Credentials
	server.auth = mauth.NewWithCookieStore(secretWithFallback(config.AuthSecret), mauth.Providers{
		"google": google.New(cred.ClientID, cred.ClientSecret, cred.RedirectURIs[0], "profile", "openid", "email"),
	})

	return server
}

// Register registers server to the specified router.
func (server *Server) Register(router *mux.Router) {
	router.HandleFunc("/", server.Dashboard)
	router.HandleFunc("/auth/logout", server.Logout)
	router.HandleFunc("/auth/google/login", server.RedirectToLogin)
	router.HandleFunc("/auth/google/callback", server.Callback)
}

// Dashboard displays the website.
func (server *Server) Dashboard(w http.ResponseWriter, r *http.Request) {
	user, _ := server.userFromSession(w, r)
	flashes := server.flashesFromSession(w, r)

	err := dashboardTemplate.Execute(w, map[string]interface{}{
		"Flashes": flashes,
		"User":    user,
	})
	if err != nil {
		server.log.Printf("failed to display template: %+v", err)
	}
}

// RedirectToLogin redirects user to the Google login page.
func (server *Server) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	// Sometimes the refresh token is still valid, hence we can try to reuse it.
	user, err := server.auth.FinishLogin("google", w, r)
	if err == nil {
		server.saveUserToSession(w, r, user)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Start the login flow.
	url, err := server.auth.BeginLogin("google", w, r)
	if err != nil {
		// Flash error and return to dashboard.
		server.flashMessage(w, r, err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		// Redirect to google login page.
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// Callback handles returning from Google login page.
//
// It will redirect to Dashboard after completing.
func (server *Server) Callback(w http.ResponseWriter, r *http.Request) {
	// First check whether we completed login to google.
	user, err := server.auth.FinishLogin("google", w, r)
	if err != nil {
		server.flashMessage(w, r, "failed to login: "+err.Error())
	} else {
		server.saveUserToSession(w, r, user)
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Logout handles logging out the user session.
func (server *Server) Logout(w http.ResponseWriter, r *http.Request) {
	// First ensure that we don't have any pending auth sessions,
	// we shouldn't have any, however it might fix some faulty
	// browser states.
	err := server.auth.Logout(w, r)
	if err != nil {
		server.log.Println(err)
	}

	// Clear the user session, if we have one.
	if sess, err := server.state.Get(r, SessionName); err == nil {
		sess.Options.MaxAge = -1
		sess.Values = make(map[interface{}]interface{})
		if err := sess.Save(r, w); err != nil {
			server.log.Println(err)
		}
	}

	// Return to dashboard.
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// saveUserToSession saves user to the current session.
func (server *Server) saveUserToSession(w http.ResponseWriter, r *http.Request, user mauth.User) {
	// This usually would fetch "user-id" from a database and store it.
	// For simplicity we'll use the information directly, however,
	// it should be easy to replace it with database management.

	// Save the user information to session.
	sess, _ := server.state.New(r, SessionName)
	sess.Values["user"] = User{
		Name:      user.Name,
		Email:     user.Email,
		UserID:    user.UserID,
		AvatarURL: user.AvatarURL,
	}
	err := sess.Save(r, w)
	if err != nil {
		server.log.Printf("unable to add user to cookie: %v", err)
	}
}

// userFromSession tries to load user from the current session.
func (server *Server) userFromSession(w http.ResponseWriter, r *http.Request) (*User, bool) {
	sess, _ := server.state.Get(r, SessionName)
	if sess == nil {
		return nil, false
	}

	v, ok := sess.Values["user"]
	if !ok {
		return nil, false
	}

	u, ok := v.(User)
	if !ok {
		delete(sess.Values, "user")
		sess.Save(r, w)
		return nil, false
	}

	return &u, true
}

func (server *Server) flashMessage(w http.ResponseWriter, r *http.Request, message string) {
	sess, _ := server.state.New(r, SessionName)
	sess.AddFlash(message)
	err := sess.Save(r, w)
	if err != nil {
		server.log.Printf("unable to add flash: %v", err)
	}
}

// flashesFromSession returns current session flashes.
func (server *Server) flashesFromSession(w http.ResponseWriter, r *http.Request) []interface{} {
	sess, _ := server.state.Get(r, SessionName)
	if sess == nil {
		return nil
	}

	flashes := sess.Flashes()
	if len(flashes) > 0 {
		err := sess.Save(r, w)
		if err != nil {
			server.log.Printf("unable to add flash: %v", err)
		}
	}

	return flashes
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
		<p><img src="{{.AvatarURL}}" ></p>
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
