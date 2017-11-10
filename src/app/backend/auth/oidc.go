// Copyright 2017 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	authApi "github.com/kubernetes/dashboard/src/app/backend/auth/api"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
)

type openIdProvider struct {
	config *oauth2.Config
	client *http.Client
}

var oidcProvider = &openIdProvider{}

func SetupOIDCProvider(c *authApi.OIDCConfig) error {
	oidcProvider = &openIdProvider{}
	if c.CAFile != "" {
		roots, err := certutil.NewPool(c.CAFile)
		if err != nil {
			return fmt.Errorf("Failed to read the CA file: %v", err)
		}
		oidcProvider.client = &http.Client{
			// Copied from http.DefaultTransport.
			Transport: net.SetTransportDefaults(&http.Transport{
				// According to golang's doc, if RootCAs is nil,
				// TLS uses the host's root CA set.
				TLSClientConfig: &tls.Config{RootCAs: roots},
			})}
	}

	ctx := context.Background()
	if oidcProvider.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, oidcProvider.client)
	}
	provider, err := oidc.NewProvider(ctx, c.IssuerURL)
	if err != nil {
		return err
	}

	oidcProvider.config = &oauth2.Config{
		Scopes:       c.Scopes,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
	}

	return nil
}

// Implements Authenticator interface.
type oidcAuthenticator struct {
	idProvider authApi.IdProvider
}

// GetAuthInfo implements Authenticator interface. See Authenticator for more information.
func (self *oidcAuthenticator) GetAuthInfo() (api.AuthInfo, error) {
	if self.idProvider.Code != "" {
		ctx := context.Background()
		if oidcProvider.client != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, oidcProvider.client)
		}
		oauth2Token, err := oidcProvider.config.Exchange(ctx, self.idProvider.Code)
		if err != nil {
			return api.AuthInfo{}, err
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return api.AuthInfo{}, fmt.Errorf("can't extrat oauth2 token")
		}
		return api.AuthInfo{Token: rawIDToken}, nil
	}
	url := oidcProvider.config.AuthCodeURL(self.idProvider.Name)

	return api.AuthInfo{}, &authApi.RedirectRequiredError{
		RedirectURL: url,
	}
}

func NewIdProviderAuthenticator(spec *authApi.LoginSpec) authApi.Authenticator {
	return &oidcAuthenticator{
		idProvider: spec.IdProvider,
	}
}
