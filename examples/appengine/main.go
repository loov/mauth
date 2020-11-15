package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	ctx := context.Background()
	logger := log.New(os.Stderr, "", log.Lshortfile)

	listenAddress := "127.0.0.1:8080"
	if os.Getenv("PORT") != "" {
		listenAddress = ":" + os.Getenv("PORT")
	}

	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	secretName := os.Getenv("GOOGLE_CREDENTIALS_SECRET_NAME")

	credentials, err := LoadCredentialsFromSecretManager(ctx, projectID, secretName)
	if err != nil {
		log.Fatal("unable to load credentials", err)
	}
	if len(credentials.RedirectURIs) == 0 {
		log.Fatal("redirect uri missing in credentials")
	}
	host, err := ExtractDomainFromURI(credentials.RedirectURIs[0])
	if err != nil {
		log.Fatal("unable to get host")
	}

	router := mux.NewRouter()
	server := NewServer(logger, Config{
		Host:        host,
		Credentials: credentials,
		UserSecret:  os.Getenv("SESSION_USER_SECRET"),
		AuthSecret:  os.Getenv("SESSION_AUTH_SECRET"),
	})
	server.Register(router)

	err = http.ListenAndServe(listenAddress, router)
	if err != nil {
		logger.Fatal(err)
	}
}
