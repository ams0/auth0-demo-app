// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/handler/handler.go
package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/alessandromr/go-auth0-api/internal/auth"     // Adjust import path
	"github.com/alessandromr/go-auth0-api/internal/config"   // Adjust import path
	"github.com/alessandromr/go-auth0-api/internal/database" // Adjust import path
	"github.com/alessandromr/go-auth0-api/internal/models"   // Adjust import path
	"github.com/ams0/go-auth0-api/internal/middleware"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

// APIHandler holds dependencies for HTTP handlers.
type APIHandler struct {
	DB         *database.DB
	AuthConfig *config.Config
	MgmtAPI    *auth.ManagementAPI
}

// NewAPIHandler creates a new APIHandler instance.
func NewAPIHandler(db *database.DB, cfg *config.Config, mgmtAPI *auth.ManagementAPI) *APIHandler {
	return &APIHandler{
		DB:         db,
		AuthConfig: cfg,
		MgmtAPI:    mgmtAPI,
	}
}

// Health handles health check requests.
func (h *APIHandler) Health(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HealthHandler] Received request: %s %s", r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := models.APIResponse{Message: "healthy"}
	log.Printf("[HealthHandler] Sending response: %+v", response)
	json.NewEncoder(w).Encode(response)
}

// Admin handles requests to the protected admin endpoint.
func (h *APIHandler) Admin(w http.ResponseWriter, r *http.Request) {
	// --- JWT Validation Result Check ---
	claimsCtx := r.Context().Value(jwtmiddleware.ContextKey{})
	if claimsCtx == nil {
		log.Println("[AdminHandler] Error: Claims not found in context (middleware issue?)")
		// Use the standard error handler logic (defined in middleware)
		middleware.AuthErrorHandler(w, r, fmt.Errorf("claims not found in context"))
		return
	}
	validatedClaims, ok := claimsCtx.(*validator.ValidatedClaims)
	if !ok {
		log.Println("[AdminHandler] Error: Failed to assert validated claims type")
		middleware.AuthErrorHandler(w, r, fmt.Errorf("failed to process token claims"))
		return
	}
	fullUserID := validatedClaims.RegisteredClaims.Subject
	log.Printf("[AdminHandler] JWT Validated. Full User ID (Subject): %s", fullUserID)

	// --- Extract Actual ID and Login Type ---
	actualUserID, loginType := extractUserIDAndType(fullUserID)
	log.Printf("[AdminHandler] Extracted Actual User ID: %s, Login Type: %s", actualUserID, loginType)

	// --- Permission Authorization Check (using Management API) ---
	requiredPermission := h.AuthConfig.RequiredAdminPermission
	hasPermission, err := h.MgmtAPI.CheckUserPermission(r.Context(), fullUserID, requiredPermission)
	if err != nil {
		log.Printf("[AdminHandler] Error checking permission '%s' for user %s: %v", requiredPermission, fullUserID, err)
		http.Error(w, "Failed to verify permissions", http.StatusInternalServerError)
		return
	}

	if !hasPermission {
		log.Printf("[AdminHandler] Authorization Failed: User %s lacks '%s' permission (checked via Management API).", fullUserID, requiredPermission)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(models.APIResponse{Message: fmt.Sprintf("Permission denied: Requires '%s' permission", requiredPermission)})
		return
	}
	log.Printf("[AdminHandler] Authorization Succeeded: User %s has '%s' permission.", fullUserID, requiredPermission)

	// --- Get User Info from Auth0 ---
	accessToken, err := extractAccessToken(r)
	if err != nil {
		log.Printf("[AdminHandler] Error extracting access token: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("[AdminHandler] Extracted Access Token (first 10 chars): %s...", accessToken[:min(10, len(accessToken))])

	userInfo, err := auth.GetUserInfo(r.Context(), h.AuthConfig.Auth0Domain, accessToken)
	if err != nil {
		log.Printf("[AdminHandler] Error getting user info: %v", err)
		// Attempt to parse the error message for status code
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "Status 401") {
			statusCode = http.StatusUnauthorized
		} else if strings.Contains(err.Error(), "Status 403") {
			statusCode = http.StatusForbidden
		} // Add more status code checks if needed
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), statusCode)
		return
	}

	// --- Database Interaction ---
	err = h.DB.CheckAndInsertUser(r.Context(), actualUserID, loginType, userInfo)
	if err != nil {
		log.Printf("[AdminHandler] Database interaction error: %v", err)
		http.Error(w, "Database interaction failed", http.StatusInternalServerError)
		return
	}

	// --- Prepare and Send Response ---
	nameToUse := getUserDisplayName(userInfo)
	response := models.APIResponse{
		Message: fmt.Sprintf("welcome %s", nameToUse),
	}

	w.Header().Set("Content-Type", "application/json")
	log.Printf("[AdminHandler] Sending response: %+v", response)
	json.NewEncoder(w).Encode(response)
}

// --- Helper Functions ---

// extractUserIDAndType splits the Auth0 subject claim (sub) into the actual user ID and login type.
func extractUserIDAndType(fullUserID string) (string, string) {
	parts := strings.Split(fullUserID, "|")
	if len(parts) == 2 {
		return parts[1], parts[0] // actualUserID, loginType
	}
	// Handle cases where the sub format might be different
	log.Printf("[Helper] User ID format does not contain '|', using full ID '%s' as actual ID and type 'auth0'", fullUserID)
	return fullUserID, "auth0" // Default login type
}

// extractAccessToken extracts the Bearer token from the Authorization header.
func extractAccessToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}
	return parts[1], nil
}

// getUserDisplayName determines the best name to display for the user.
func getUserDisplayName(userInfo *models.UserInfo) string {
	if userInfo.Nickname != "" {
		return userInfo.Nickname
	}
	if userInfo.Name != "" {
		return userInfo.Name
	}
	if userInfo.Email != "" {
		return userInfo.Email
	}
	log.Println("[Helper] No suitable display name found, using fallback 'user'")
	return "user" // Final fallback
}

// min is a simple helper function.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
