// Copyright (c) 2020 Egon Elbre
// Copyright (c) 2014 Mark Bates
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package mauth implements OAuth2 authentication for providers in github.com/markbates/goth/providers.
// It's largely based on github.com/markbates/goth/gothic, however, without global state.
package mauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
)

var (
	// ErrInvalidProvider is returned when an invalid provider is used in BeginLogin or FinishLogin.
	ErrInvalidProvider = errors.New("invalid provider")
)

// Sessions manages sessions for multiple goth.Provider-s.
type Sessions struct {
	providers   Providers
	store       sessions.Store
	sessionName string
}

// NewWithCookieStore creates a new authentication manager that uses CookieStore with default name.
func NewWithCookieStore(secret []byte, providers Providers) *Sessions {
	if len(secret) == 0 {
		var key [64]byte
		_, err := rand.Read(key[:])
		if err != nil {
			panic("rand read failed: " + err.Error())
		}
		secret = key[:]
	}

	cookies := sessions.NewCookieStore(secret)
	cookies.Options.HttpOnly = true
	cookies.Options.Secure = true
	return New(cookies, "_mauth", providers)
}

// New creates a new authentication manager.
func New(store sessions.Store, name string, providers Providers) *Sessions {
	return &Sessions{
		providers:   providers,
		store:       store,
		sessionName: name,
	}
}

// Providers is a list of OAuth2 providers.
type Providers = goth.Providers

// Provider is a single OAuth2 provider from github.com/markbates/provider.
type Provider = goth.Provider

// User is authentication information about the user.
type User = goth.User

// Providers returns the list of providers.
func (s *Sessions) Providers() Providers { return s.providers }

// BeginLogin redirects request to provider OAuth login page.
//
// If it returns error, it has not redirected the page.
func (s *Sessions) BeginLogin(providerName string, w http.ResponseWriter, r *http.Request) (url string, _ error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrInvalidProvider, providerName)
	}

	var tokenBytes [64]byte
	_, err := io.ReadFull(rand.Reader, tokenBytes[:])
	if err != nil {
		panic(err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes[:])

	session, err := provider.BeginAuth(token)
	if err != nil {
		return "", fmt.Errorf("unable to begin auth: %w", err)
	}

	url, err = session.GetAuthURL()
	if err != nil {
		return "", fmt.Errorf("unable to get redirect url: %w", err)
	}

	err = s.set(providerName, session.Marshal(), w, r)
	if err != nil {
		return "", fmt.Errorf("unable to save auth session: %w", err)
	}

	return url, nil
}

// FinishLogin should be called as a callback after authentication.
func (s *Sessions) FinishLogin(providerName string, w http.ResponseWriter, r *http.Request) (User, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return User{}, fmt.Errorf("%w: %q", ErrInvalidProvider, providerName)
	}

	// clear any previous authentication
	defer func() { _ = s.Logout(w, r) }()

	value, err := s.get(providerName, w, r)
	if err != nil {
		return User{}, fmt.Errorf("failed to get pending auth: %w", err)
	}
	session, err := provider.UnmarshalSession(value)
	if err != nil {
		return User{}, fmt.Errorf("invalid session: %w", err)
	}

	if err := verifyStateNonce(r, session); err != nil {
		return User{}, fmt.Errorf("unable to verify session: %w", err)
	}

	user, err := provider.FetchUser(session)
	if err == nil {
		return user, nil
	}

	params := r.URL.Query()
	if params.Encode() == "" && r.Method == "POST" {
		r.ParseForm()
		params = r.Form
	}

	// get new token and retry fetch
	_, err = session.Authorize(provider, params)
	if err != nil {
		return User{}, fmt.Errorf("unable to authorize: %w", err)
	}

	err = s.set(providerName, session.Marshal(), w, r)
	if err != nil {
		return User{}, fmt.Errorf("unable to save auth session: %w", err)
	}

	user, err = provider.FetchUser(session)
	if err != nil {
		return User{}, fmt.Errorf("unable to fetch user: %w", err)
	}
	return user, nil
}

// Logout clears any associated sessions.
func (s *Sessions) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := s.store.Get(r, s.sessionName)
	if err != nil {
		// no session pending
		return nil
	}

	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})
	err = session.Save(r, w)
	if err != nil {
		return fmt.Errorf("could not delete user session: %w", err)
	}
	return nil
}

// set sests string value for the session.
func (s *Sessions) set(key, value string, w http.ResponseWriter, r *http.Request) error {
	session, _ := s.store.New(r, s.sessionName)
	session.Values[key] = value
	err := s.store.Save(r, w, session)
	if err != nil {
		return fmt.Errorf("unable to update session: %w", err)
	}
	return nil
}

// get loads string value from the session.
func (s *Sessions) get(key string, w http.ResponseWriter, r *http.Request) (string, error) {
	session, _ := s.store.New(r, s.sessionName)
	v, ok := session.Values[key]
	if !ok {
		return "", fmt.Errorf("value not found: %q", key)
	}
	vstr, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("value %T is not string", v)
	}
	return vstr, nil
}

// verifyStateNonce verifies that the request "state" parameter matches goth session.
func verifyStateNonce(r *http.Request, session goth.Session) error {
	authurl, err := session.GetAuthURL()
	if err != nil {
		return fmt.Errorf("unable to get original auth url: %w", err)
	}

	u, err := url.Parse(authurl)
	if err != nil {
		return fmt.Errorf("invalid auth url %q: %w", authurl, err)
	}

	originalState := u.Query().Get("state")
	requestState := r.URL.Query().Get("state")

	if subtle.ConstantTimeCompare([]byte(originalState), []byte(requestState)) != 1 {
		return fmt.Errorf("state token does not match")
	}

	return nil
}
