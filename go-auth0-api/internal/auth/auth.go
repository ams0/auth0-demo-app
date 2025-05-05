// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/auth/auth.go
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/alessandromr/go-auth0-api/internal/config" // Adjust import path
	"github.com/alessandromr/go-auth0-api/internal/models" // Adjust import path
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// Validator wraps the Auth0 JWT validator.
type Validator struct {
	*validator.Validator
}

// ManagementAPI holds configuration and cache for the Auth0 Management API.
type ManagementAPI struct {
	Config *config.Config
	Cache  *models.ManagementTokenCache
	Mutex  sync.Mutex
}

// NewValidator creates a new JWT validator instance.
func NewValidator(cfg *config.Config) (*Validator, error) {
	issuerURL, err := url.Parse("https://" + cfg.Auth0Domain + "/")
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer URL: %w", err)
	}
	log.Printf("Auth Validator: Issuer URL: %s", issuerURL.String())

	provider := jwks.NewProvider(issuerURL)
	log.Println("Auth Validator: JWKS Provider created.")

	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256, // Expected signing algorithm
		issuerURL.String(),
		cfg.Auth0Audiences,
		validator.WithCustomClaims(func() validator.CustomClaims {
			return &models.CustomClaims{} // Use model from models package
		}),
		// Add other options like validator.WithAllowedClockSkew(time.Minute) if needed
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the JWT validator: %w", err)
	}
	log.Println("Auth Validator: JWT Validator created successfully.")
	return &Validator{jwtValidator}, nil
}

// NewManagementAPI creates a new ManagementAPI instance.
func NewManagementAPI(cfg *config.Config) *ManagementAPI {
	return &ManagementAPI{
		Config: cfg,
		Cache:  &models.ManagementTokenCache{}, // Initialize cache
	}
}

// getManagementAPIToken fetches a token for the Management API, caching it.
func (m *ManagementAPI) getManagementAPIToken(ctx context.Context) (string, error) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	// Check cache
	if m.Cache.Token != "" && time.Now().Before(m.Cache.Expiry) {
		log.Println("[MgmtAPI] Using cached Management API token.")
		return m.Cache.Token, nil
	}
	log.Println("[MgmtAPI] Cache miss or expired. Fetching new Management API token...")

	// Prepare request to Auth0 /oauth/token endpoint
	tokenURL := "https://" + m.Config.Auth0Domain + "/oauth/token"
	audience := "https://" + m.Config.Auth0Domain + "/api/v2/" // Management API audience

	payload := map[string]string{
		"client_id":     m.Config.Auth0MgmtClientID,
		"client_secret": m.Config.Auth0MgmtClientSecret,
		"audience":      audience,
		"grant_type":    "client_credentials",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[MgmtAPI] Error marshaling token request payload: %v", err)
		return "", fmt.Errorf("failed to create token request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("[MgmtAPI] Error creating token request: %v", err)
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MgmtAPI] Error making token request: %v", err)
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[MgmtAPI] Error response from token endpoint (%d): %s", resp.StatusCode, string(bodyBytes))
		return "", fmt.Errorf("failed to fetch token, status: %d", resp.StatusCode)
	}

	var tokenResponse models.ManagementTokenResponse // Use model from models package
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Printf("[MgmtAPI] Error decoding token response: %v", err)
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Cache the token and its expiry
	m.Cache.Token = tokenResponse.AccessToken
	m.Cache.Expiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	log.Printf("[MgmtAPI] New Management API token cached. Expires at: %s", m.Cache.Expiry)

	return m.Cache.Token, nil
}

// CheckUserPermission checks if a user has a specific permission via the Auth0 Management API.
func (m *ManagementAPI) CheckUserPermission(ctx context.Context, userID, requiredPermission string) (bool, error) {
	token, err := m.getManagementAPIToken(ctx)
	if err != nil {
		log.Printf("[MgmtAPI CheckPerm] Error getting management token: %v", err)
		// Return a generic server error
		return false, fmt.Errorf("failed to communicate with authentication service")
	}

	// URL encode the userID in case it contains special characters
	permissionsURL := fmt.Sprintf("https://%s/api/v2/users/%s/permissions", m.Config.Auth0Domain, url.PathEscape(userID))
	log.Printf("[MgmtAPI CheckPerm] Preparing to call Auth0 Management API endpoint: %s", permissionsURL)

	req, err := http.NewRequestWithContext(ctx, "GET", permissionsURL, nil)
	if err != nil {
		log.Printf("[MgmtAPI CheckPerm] Error creating permissions request for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to create permissions request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	log.Printf("[MgmtAPI CheckPerm] Fetching permissions for user %s from %s", userID, permissionsURL)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MgmtAPI CheckPerm] Error fetching permissions for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to fetch permissions")
	}
	defer resp.Body.Close()

	log.Printf("[MgmtAPI CheckPerm] Received response status: %s for user %s from %s", resp.Status, userID, permissionsURL)

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[MgmtAPI CheckPerm] Error response (%d) fetching permissions for user %s: %s", resp.StatusCode, userID, string(bodyBytes))
		if resp.StatusCode == http.StatusNotFound {
			return false, fmt.Errorf("user not found or permissions inaccessible")
		}
		return false, fmt.Errorf("failed to fetch permissions (status %d)", resp.StatusCode)
	}

	var permissions []models.UserPermission // Use model from models package
	if err := json.NewDecoder(resp.Body).Decode(&permissions); err != nil {
		log.Printf("[MgmtAPI CheckPerm] Error decoding permissions for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to decode permissions response")
	}
	log.Printf("[MgmtAPI CheckPerm] Fetched %d permissions for user %s", len(permissions), userID)

	for _, p := range permissions {
		if p.Name == requiredPermission {
			log.Printf("[MgmtAPI CheckPerm] User %s HAS required permission '%s'", userID, requiredPermission)
			return true, nil
		}
	}

	log.Printf("[MgmtAPI CheckPerm] User %s does NOT have required permission '%s'. Found permissions: %+v", userID, requiredPermission, permissions)
	return false, nil // Permission not found, not an error state itself
}

// GetUserInfo calls the /userinfo endpoint to get user details.
func GetUserInfo(ctx context.Context, domain, accessToken string) (*models.UserInfo, error) {
	userInfoURL := "https://" + domain + "/userinfo"
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		log.Printf("[GetUserInfo] Error creating UserInfo request: %v", err)
		return nil, fmt.Errorf("failed to create request to UserInfo endpoint: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	log.Printf("[GetUserInfo] Calling UserInfo endpoint: %s", userInfoURL)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[GetUserInfo] Error calling UserInfo endpoint: %v", err)
		return nil, fmt.Errorf("failed to call UserInfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		bodyString := ""
		if readErr != nil {
			log.Printf("[GetUserInfo] Error reading UserInfo error response body: %v", readErr)
			bodyString = "(could not read error body)"
		} else {
			bodyString = string(bodyBytes)
		}
		log.Printf("[GetUserInfo] Error from UserInfo endpoint: Status %d, Body: %s", resp.StatusCode, bodyString)
		// Consider returning a more structured error if needed
		return nil, fmt.Errorf("failed to get user info: Status %d - %s", resp.StatusCode, bodyString)
	}

	var userInfo models.UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Printf("[GetUserInfo] Error decoding UserInfo response: %v", err)
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	log.Printf("[GetUserInfo] UserInfo received: %+v", userInfo)
	return &userInfo, nil
}
