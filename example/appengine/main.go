package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/twitter"

	"loov.dev/mauth"
)

func main() {
	defaultAddr := ""
	if os.Getenv("PORT") != "" {
		defaultAddr = ":" + os.Getenv("PORT")
	}
	if defaultAddr == "" {
		defaultAddr = "127.0.0.1:8080"
	}

	authsecret := flag.String("auth.secret", "", "authentication session secret")
	listen := flag.String("listen", defaultAddr, "address to listen on")
	host := flag.String("host", "https://storj-jam.appspot.com", "public host")

	providers := []*ProviderCredential{
		{Name: "google", New: func(key, value, callback string) mauth.Provider { return google.New(key, value, callback) }},
		{Name: "twitter", New: func(key, value, callback string) mauth.Provider { return twitter.New(key, value, callback) }},
		{Name: "facebook", New: func(key, value, callback string) mauth.Provider { return facebook.New(key, value, callback) }},
		{Name: "github", New: func(key, value, callback string) mauth.Provider { return github.New(key, value, callback) }},
	}
	for _, provider := range providers {
		provider.AddFlag(flag.CommandLine)
	}
	flag.Parse()

	if *host == "" {
		*host = *listen
	}

	config := Config{
		Host:       *host,
		AuthSecret: *authsecret,
		Providers:  providers,
	}

	logger := log.New(os.Stderr, "", log.Lshortfile)

	router := mux.NewRouter()
	server := NewServer(logger, config)
	server.Register(router)

	err := http.ListenAndServe(*listen, router)
	if err != nil {
		logger.Fatal(err)
	}
}

const SessionName = "example"

type Config struct {
	Host       string
	AuthSecret string

	Providers []*ProviderCredential
}

type ProviderCredential struct {
	Name string
	URL  template.URL
	New  func(key, secret, callback string) mauth.Provider

	Key    string
	Secret string
}

func (ks *ProviderCredential) Empty() bool { return ks.Key == "" }

func (ks *ProviderCredential) AddFlag(fs *flag.FlagSet) {
	lower := strings.ToLower(ks.Name)
	upper := strings.ToUpper(ks.Name)
	fs.StringVar(&ks.Key, lower+".key", os.Getenv(upper+"_KEY"), ks.Name+" OAuth2 client key (`$"+upper+"_KEY`)")
	fs.StringVar(&ks.Secret, lower+".secret", os.Getenv(upper+"_SECRET"), ks.Name+" OAuth2 client secret (`$"+upper+"_SECRET`)")
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

	state := sessions.NewCookieStore([]byte("othersecret"))
	state.Options.HttpOnly = true
	state.Options.Secure = true
	server.state = state

	providers := mauth.Providers{}
	for _, cred := range config.Providers {
		cred.URL = template.URL(config.Host + "/auth/" + cred.Name + "/login")
		if cred.Empty() {
			continue
		}
		providers[cred.Name] = cred.New(cred.Key, cred.Secret, config.Host+"/auth/"+cred.Name+"/callback")
	}

	server.auth = mauth.NewWithCookieStore(config.AuthSecret, providers)

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

	err := dashboard.Execute(w, map[string]interface{}{
		"Flashes":   flashes,
		"User":      user,
		"Providers": server.config.Providers,
	})
	if err != nil {
		server.log.Printf("failed to display template: %+v", err)
	}
}

var dashboard = template.Must(template.New("").Parse(`<!DOCTYPE html>
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
		<p>Name: {{.Name}} [{{.LastName}}, {{.FirstName}}]</p>
		<p>Email: {{.Email}}</p>
		<p>NickName: {{.NickName}}</p>
		<p>UserID: {{.UserID}}</p>
		<p>ExpiresAt: {{.ExpiresAt}}</p>
	</div>
	{{ else }}
	<p>User not logged in.</p>
	{{ end }}

	<h2>Login</h2>
	<div>
	{{ range $provider := .Providers }}
	<p><a href="{{$provider.URL}}" {{if $provider.Empty}}disabled{{end}}>{{$provider.Name}}</a></p>
	{{ end }}
	</div>
</body>
</html>
`))

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
