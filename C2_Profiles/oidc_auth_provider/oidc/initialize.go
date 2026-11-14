package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MythicMeta/MythicContainer/authstructs"
	"github.com/MythicMeta/MythicContainer/utils/sharedStructs"
	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
)

const version = "1.0.0"
const name = "oidc"

const cookieStateName = "oidc_state"

type Config struct {
	// Issuer is the URL identifier for the service. For example: "https://accounts.google.com"
	// or "https://login.salesforce.com".
	Issuer string `json:"issuer"`

	// ClientID is the identifier issued to the client during the registration process.
	ClientID string `json:"client_id"`

	// ClientSecret is the secret issued to the client during the registration process.
	ClientSecret string `json:"client_secret"`

	// RedirectURL is the URL to which the authorization server will send the user after granting authorization.
	// <MYTHIC_URL>/auth_acs/OIDC/OIDC
	RedirectURL string `json:"redirect_url"`

	// MTLSCertFile is the filename of the client certificate uploaded through
	// the auth container's file browser. Leave empty to disable client auth.
	MTLSCertFile string `json:"mtls_cert_file"`

	// MTLSKeyFile is the filename of the client private key uploaded through
	// the auth container's file browser.
	MTLSKeyFile string `json:"mtls_key_file"`

	// MTLSCAFile is the filename of the CA bundle uploaded through the auth
	// container's file browser. When set, it replaces the system trust store
	// for OIDC requests.
	MTLSCAFile string `json:"mtls_ca_file"`
}

func randomString(length int) string {
	res := make([]byte, length)
	_, _ = rand.Read(res)
	return fmt.Sprintf("%x", res)
}

func loadConfig() (*Config, error) {
	configBytes, err := os.ReadFile(filepath.Join(".", "config.json"))
	if err != nil {
		return nil, err
	}
	var cfg Config

	err = json.Unmarshal(configBytes, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func oauth2Config(ctx context.Context, config *Config) (*oidc.Provider, *oauth2.Config, error) {
	oidcProvider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, nil, err
	}

	return oidcProvider, &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),

		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}

func Initialize() {
	auth := authstructs.AuthDefinition{
		Name:           name,
		SemVer:         version,
		Description:    "Integration with OpenID Connect (OIDC) identity provider for user authentication",
		IDPServices:    []string{name},
		NonIDPServices: nil,
		OnContainerStartFunction: func(message sharedStructs.ContainerOnStartMessage) sharedStructs.ContainerOnStartMessageResponse {
			return sharedStructs.ContainerOnStartMessageResponse{}
		},
		GetIDPMetadata: func(message authstructs.GetIDPMetadataMessage) authstructs.GetIDPMetadataMessageResponse {
			response := authstructs.GetIDPMetadataMessageResponse{
				Success: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				return response
			}

			oidcProvider, _, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				return response
			}

			endpoint := oidcProvider.Endpoint()
			metadata := fmt.Sprintf("Issuer: %s, AuthURL: %s, TokenURL: %s", cfg.Issuer, endpoint.AuthURL, endpoint.TokenURL)

			response.Success = true
			response.Metadata = metadata
			return response
		},
		GetIDPRedirect: func(message authstructs.GetIDPRedirectMessage) authstructs.GetIDPRedirectMessageResponse {
			response := authstructs.GetIDPRedirectMessageResponse{
				Success: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				return response
			}

			_, oauth2Config, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				return response
			}

			state := randomString(16)
			cookies := make(map[string]string)
			cookies[cookieStateName] = state

			response.Success = true
			response.RedirectURL = oauth2Config.AuthCodeURL(state)
			response.RedirectCookies = cookies

			return response
		},
		ProcessIDPResponse: func(message authstructs.ProcessIDPResponseMessage) authstructs.ProcessIDPResponseMessageResponse {
			response := authstructs.ProcessIDPResponseMessageResponse{
				SuccessfulAuthentication: false,
			}

			cfg, err := loadConfig()
			if err != nil {
				response.Error = fmt.Sprintf("Failed to load config: %v", err)
				return response
			}

			stateCookie, ok := message.RequestCookies[cookieStateName]
			if !ok {
				response.Error = "Missing state cookie"
				return response
			}

			stateCookie = strings.Replace(stateCookie, cookieStateName+"=", "", 1)

			if stateCookie != message.RequestQuery["state"] {
				response.Error = "Invalid state parameter"
				return response
			}

			ctx, err := withIdPClient(context.Background(), cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to configure mTLS: %v", err)
				return response
			}

			oidcProvider, oauth2Config, err := oauth2Config(ctx, cfg)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to create OAuth2 config: %v", err)
				return response
			}

			verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

			oauth2Token, err := oauth2Config.Exchange(ctx, message.RequestQuery["code"])
			if err != nil {
				response.Error = fmt.Sprintf("Failed to exchange code: %v", err)
				return response
			}

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				response.Error = "Missing ID Token"
				return response
			}

			// Parse and verify ID Token payload.
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				response.Error = fmt.Sprintf("Failed to verify ID Token: %v", err)
				return response
			}

			// Extract custom claims
			var claims struct {
				Email    string `json:"email"`
				Verified bool   `json:"email_verified"`
			}

			if err := idToken.Claims(&claims); err != nil {
				response.Error = fmt.Sprintf("Failed to extract claims: %v", err)
				return response
			}

			if !claims.Verified {
				response.Error = "Email not verified"
				return response
			}

			response.SuccessfulAuthentication = true
			response.Email = claims.Email

			return response
		},
		GetNonIDPMetadata: func(message authstructs.GetNonIDPMetadataMessage) authstructs.GetNonIDPMetadataMessageResponse {
			return authstructs.GetNonIDPMetadataMessageResponse{
				Success:  false,
				Metadata: "Not Supported",
			}
		},
		GetNonIDPRedirect: func(message authstructs.GetNonIDPRedirectMessage) authstructs.GetNonIDPRedirectMessageResponse {
			return authstructs.GetNonIDPRedirectMessageResponse{
				Success:       false,
				RequestFields: nil,
			}
		},
		ProcessNonIDPResponse: func(message authstructs.ProcessNonIDPResponseMessage) authstructs.ProcessNonIDPResponseMessageResponse {
			return authstructs.ProcessNonIDPResponseMessageResponse{
				SuccessfulAuthentication: false,
			}
		},
	}
	authstructs.AllAuthData.Get(name).AddAuthDefinition(auth)
}
