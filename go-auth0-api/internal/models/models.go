// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/models/models.go
package models

import (
	"context"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// UserPermission represents a permission assigned to a user from the Management API
type UserPermission struct {
	Name        string `json:"permission_name"`
	Description string `json:"description"`
	ServerName  string `json:"resource_server_name"`
	ServerID    string `json:"resource_server_identifier"`
}

// UserInfo represents the structure of the response from the /userinfo endpoint
type UserInfo struct {
	Sub           string `json:"sub"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Nickname      string `json:"nickname"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	UpdatedAt     string `json:"updated_at"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	// Add other fields as needed based on your Auth0 configuration and requested scopes
}

// CustomClaims now includes the permissions claim.
// Adjust the json tag if your claim name is different.
type CustomClaims struct {
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"` // Assumed claim name for permissions
}

// Validate implements validator.CustomClaims interface.
func (c *CustomClaims) Validate(ctx context.Context) error {
	// You could add validation specific to permissions here if needed
	return nil
}

// Ensure CustomClaims implements the validator.CustomClaims interface.
var _ validator.CustomClaims = &CustomClaims{}

// APIResponse is the structure for our API responses
type APIResponse struct {
	Message string `json:"message"`
}

// ManagementTokenResponse represents the structure of the response from Auth0 /oauth/token
type ManagementTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // Seconds until expiry
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// Permission represents a single permission object from the Management API
type Permission struct {
	Name        string `json:"permission_name"`
	Description string `json:"description"`
	Source      struct {
		Type string `json:"source_type"`
		ID   string `json:"source_id"`
		Name string `json:"source_name"`
	} `json:"resource_server_identifier"` // Note: Field name might differ slightly based on Auth0 config
}

// ManagementTokenCache holds the cached Management API token and its expiry time.
type ManagementTokenCache struct {
	Token  string
	Expiry time.Time
}
