package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// Credentials can be downloaded from Google Cloud credentials.
type Credentials struct {
	ProjectID    string   `json:"project_id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

// LoadCredentialsFromSecretManager loads secret from secret manager.
func LoadCredentialsFromSecretManager(ctx context.Context, projectID, secretName string) (Credentials, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return Credentials{}, fmt.Errorf("unable to create secret manager: %w", err)
	}
	defer func() { _ = client.Close() }()

	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)
	secret, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	})
	if err != nil {
		return Credentials{}, fmt.Errorf("unable to fetch secret %q: %w", resourceName, err)
	}

	var credentials struct {
		Web Credentials `json:"web"`
	}

	err = json.Unmarshal(secret.Payload.Data, &credentials)
	if err != nil {
		return Credentials{}, fmt.Errorf("credentials in secret are not valid: %w", err)
	}

	if credentials.Web.ClientID == "" || credentials.Web.ClientSecret == "" {
		return Credentials{}, fmt.Errorf("credentials in secret are missing: %w", err)
	}

	return credentials.Web, nil
}

// ExtractDomainFromURI extracts domain from
func ExtractDomainFromURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid uri %q: %w", uri, err)
	}

	return u.Scheme + u.Host, nil
}
