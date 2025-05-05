// Go API service that validates Auth0 JWT tokens and extracts the given_name claim
package main

import (
	"bytes" // Import bytes for request body
	"context"
	"database/sql" // Import database/sql
	"encoding/json"
	"fmt"
	"io" // Import io package for reading response body
	"log"
	"net/http" // Import for dumping request details (optional)
	"net/url"
	"os"
	"strings"
	"sync" // Import sync for mutex
	"time" // Import time for token expiry

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq" // Import the postgres driver (note the underscore)
)

// --- Constants ---
const requiredAdminPermission = "all-users" // Define the required permission for the admin endpoint

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

// APIResponse is the structure for our API responses
type APIResponse struct {
	Message string `json:"message"`
}

// Ensure CustomClaims implements the validator.CustomClaims interface.
var _ validator.CustomClaims = &CustomClaims{}

// Global variable for the database connection pool
var db *sql.DB

// --- Management API Token Cache ---
var (
	managementToken       string
	managementTokenExpiry time.Time
	managementTokenMutex  sync.Mutex // Protects access to token and expiry
)

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

// getManagementAPIToken fetches a token for the Management API, caching it.
func getManagementAPIToken(ctx context.Context, domain, clientID, clientSecret string) (string, error) {
	managementTokenMutex.Lock()
	defer managementTokenMutex.Unlock()

	// Check cache
	if managementToken != "" && time.Now().Before(managementTokenExpiry) {
		log.Println("[getManagementAPIToken] Using cached Management API token.")
		return managementToken, nil
	}
	log.Println("[getManagementAPIToken] Cache miss or expired. Fetching new Management API token...")

	// Prepare request to Auth0 /oauth/token endpoint
	tokenURL := "https://" + domain + "/oauth/token"
	audience := "https://" + domain + "/api/v2/" // Management API audience

	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      audience,
		"grant_type":    "client_credentials",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[getManagementAPIToken] Error marshaling token request payload: %v", err)
		return "", fmt.Errorf("failed to create token request payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("[getManagementAPIToken] Error creating token request: %v", err)
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second} // Add a timeout
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[getManagementAPIToken] Error making token request: %v", err)
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[getManagementAPIToken] Error response from token endpoint: %s", string(bodyBytes))
		return "", fmt.Errorf("failed to fetch token, status: %d", resp.StatusCode)
	}

	var tokenResponse ManagementTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Printf("[getManagementAPIToken] Error decoding token response: %v", err)
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Cache the token and its expiry
	managementToken = tokenResponse.AccessToken
	managementTokenExpiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	log.Printf("[getManagementAPIToken] New Management API token cached. Expires at: %s", managementTokenExpiry)

	return managementToken, nil
}

// checkUserPermission checks if a user has a specific permission via the Auth0 Management API.
func checkUserPermission(ctx context.Context, userID, requiredPermission string) (bool, error) {
	domain := os.Getenv("AUTH0_DOMAIN")
	mgmtClientID := os.Getenv("AUTH0_MANAGEMENT_CLIENT_ID")
	mgmtClientSecret := os.Getenv("AUTH0_MANAGEMENT_CLIENT_SECRET")

	if domain == "" || mgmtClientID == "" || mgmtClientSecret == "" {
		log.Println("[checkUserPermission] Error: Management API credentials (AUTH0_DOMAIN, AUTH0_MANAGEMENT_CLIENT_ID, AUTH0_MANAGEMENT_CLIENT_SECRET) not configured.")
		// Return a generic server error to the client, but log the specific issue
		return false, fmt.Errorf("server configuration error")
	}

	token, err := getManagementAPIToken(ctx, domain, mgmtClientID, mgmtClientSecret)
	if err != nil {
		log.Printf("[checkUserPermission] Error getting management token: %v", err)
		// Return a generic server error
		return false, fmt.Errorf("failed to communicate with authentication service")
	}

	// URL encode the userID in case it contains special characters
	permissionsURL := fmt.Sprintf("https://%s/api/v2/users/%s/permissions", domain, url.PathEscape(userID))
	log.Printf("[checkUserPermission] Preparing to call Auth0 Management API endpoint: %s", permissionsURL) // <<< Log the endpoint URL
	req, err := http.NewRequestWithContext(ctx, "GET", permissionsURL, nil)
	if err != nil {
		log.Printf("[checkUserPermission] Error creating permissions request for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to create permissions request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second} // Use a reasonable timeout
	log.Printf("[checkUserPermission] Fetching permissions for user %s from %s", userID, permissionsURL)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[checkUserPermission] Error fetching permissions for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to fetch permissions")
	}
	defer resp.Body.Close()

	log.Printf("[checkUserPermission] Received response status: %s for user %s from %s", resp.Status, userID, permissionsURL) // <<< Log the response status

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		// Log the detailed error, but return a generic one
		log.Printf("[checkUserPermission] Error response (%d) fetching permissions for user %s: %s", resp.StatusCode, userID, string(bodyBytes))
		// Handle specific cases like 404 Not Found if the user doesn't exist in Management API context
		if resp.StatusCode == http.StatusNotFound {
			return false, fmt.Errorf("user not found or permissions inaccessible")
		}
		return false, fmt.Errorf("failed to fetch permissions (status %d)", resp.StatusCode)
	}

	var permissions []UserPermission // Use the new struct
	if err := json.NewDecoder(resp.Body).Decode(&permissions); err != nil {
		log.Printf("[checkUserPermission] Error decoding permissions for user %s: %v", userID, err)
		return false, fmt.Errorf("failed to decode permissions response")
	}
	log.Printf("[checkUserPermission] Fetched %d permissions for user %s", len(permissions), userID)

	for _, p := range permissions {
		if p.Name == requiredPermission {
			log.Printf("[checkUserPermission] User %s HAS required permission '%s'", userID, requiredPermission)
			return true, nil
		}
	}

	// Log the permissions found for debugging, but don't expose them in errors
	log.Printf("[checkUserPermission] User %s does NOT have required permission '%s'. Found permissions: %+v", userID, requiredPermission, permissions)
	return false, nil // Permission not found, not an error state itself
}

// --- Middleware Definitions ---

// loggingMiddleware logs incoming requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[LoggingMiddleware] Started %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Create a response writer wrapper to capture status code
		// (This is a simple example; more sophisticated wrappers exist)
		wrapper := &responseWriterWrapper{ResponseWriter: w}

		next.ServeHTTP(wrapper, r)

		log.Printf(
			"[LoggingMiddleware] Completed %s %s in %v with status %d",
			r.Method,
			r.URL.Path,
			time.Since(start),
			wrapper.status,
		)
	})
}

// responseWriterWrapper helps capture the status code for logging
type responseWriterWrapper struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		// Default to 200 OK if WriteHeader wasn't called before Write
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// ensureValidToken creates the JWT validation middleware
func ensureValidToken(val *validator.Validator, errorHandler func(http.ResponseWriter, *http.Request, error)) func(http.Handler) http.Handler {
	// Create the middleware instance using the provided validator and error handler
	middleware := jwtmiddleware.New(val.ValidateToken, jwtmiddleware.WithErrorHandler(errorHandler))

	// Return a function that conforms to the standard middleware pattern (func(http.Handler) http.Handler)
	return func(next http.Handler) http.Handler {
		// Apply the JWT middleware to the next handler
		return middleware.CheckJWT(next)
	}
}

// --- End Middleware Definitions ---

func main() {
	log.Println("Starting main function...")
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// --- Database Connection Setup ---
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbSSLMode := os.Getenv("DB_SSLMODE") // e.g., "disable", "require", "verify-full"

	// --- Auth0 Management API Credentials Check ---
	mgmtClientID := os.Getenv("AUTH0_MANAGEMENT_CLIENT_ID")
	mgmtClientSecret := os.Getenv("AUTH0_MANAGEMENT_CLIENT_SECRET")
	domain := os.Getenv("AUTH0_DOMAIN") // Domain is needed by both JWT validation and Management API

	if domain == "" {
		log.Fatal("Environment variable AUTH0_DOMAIN must be set")
	}
	if mgmtClientID == "" || mgmtClientSecret == "" {
		log.Fatal("Environment variables AUTH0_MANAGEMENT_CLIENT_ID and AUTH0_MANAGEMENT_CLIENT_SECRET must be set for permission checks")
	}
	// --- End Auth0 Management API Credentials Check ---

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		log.Fatal("Database environment variables (DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME) must be set")
	}
	if dbSSLMode == "" {
		dbSSLMode = "disable" // Default SSL mode
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)

	var err error // Declare err here
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close() // Ensure DB connection is closed when main exits

	// Check if the connection is actually established
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Successfully connected to PostgreSQL database.")
	// --- End Database Connection Setup ---

	// Set up a router
	mux := http.NewServeMux()

	// Get the Auth0 domain and audiences from environment variables
	// Read comma-separated audiences
	audiencesStr := os.Getenv("AUTH0_AUDIENCES")
	log.Printf("Auth0 Domain: %s, Audiences String: %s", domain, audiencesStr) // Updated log

	if audiencesStr == "" {
		log.Fatal("Environment variable AUTH0_AUDIENCES must be set") // Updated error message
	}

	// Split the audiences string into a slice
	audiences := strings.Split(audiencesStr, ",")
	// Trim whitespace from each audience
	for i := range audiences {
		audiences[i] = strings.TrimSpace(audiences[i])
	}
	log.Printf("Configured Audiences: %v", audiences) // Log the parsed audiences

	// Create the JWT validator
	issuerURL, err := url.Parse("https://" + domain + "/")
	if err != nil {
		log.Fatalf("Failed to parse issuer URL: %v", err)
	}
	log.Printf("Issuer URL: %s", issuerURL.String()) // Added log

	// Sets up the JWKS provider
	provider := jwks.NewProvider(issuerURL)
	log.Println("JWKS Provider created.") // Added log

	// Set up the validator with the JWKS provider and multiple audiences
	jwtValidator, err := validator.New(
		provider.KeyFunc,   // KeyFunc fetches the public key from the JWKS endpoint
		validator.RS256,    // Expected signing algorithm (e.g., RS256)
		issuerURL.String(), // Issuer URL
		audiences,          // Pass the slice of expected audiences
		validator.WithCustomClaims(func() validator.CustomClaims { // Register custom claims struct
			return &CustomClaims{}
		}),
	)
	if err != nil {
		log.Fatalf("Failed to set up the JWT validator: %v", err)
	}
	log.Println("JWT Validator created.") // Added log

	// Error handler for the middleware (signature is correct)
	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[ErrorHandler] Responding to auth failure. Error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIResponse{Message: "Authentication failed: " + err.Error()})
	}

	// Admin endpoint (remains mostly the same, expects claims in context)
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// --- JWT Validation Result Check ---
		// The JWT middleware already validated the token and put claims in context.
		claimsCtx := r.Context().Value(jwtmiddleware.ContextKey{})
		if claimsCtx == nil {
			log.Println("[AdminHandler] Error: Claims not found in context (middleware issue?)")
			// Use the standard error handler logic
			errorHandler(w, r, fmt.Errorf("claims not found in context"))
			return
		}
		validatedClaims, ok := claimsCtx.(*validator.ValidatedClaims)
		if !ok {
			log.Println("[AdminHandler] Error: Failed to assert validated claims type")
			errorHandler(w, r, fmt.Errorf("failed to process token claims"))
			return
		}
		// Log the subject (user ID) from the validated token
		fullUserID := validatedClaims.RegisteredClaims.Subject // Keep the original full ID
		log.Printf("[AdminHandler] JWT Validated. Full User ID (Subject): %s", fullUserID)

		// --- Extract Actual ID and Login Type ---
		var actualUserID string
		var loginType string
		parts := strings.Split(fullUserID, "|")
		if len(parts) == 2 {
			loginType = parts[0]
			actualUserID = parts[1]
		} else {
			// Handle cases where the sub format might be different (e.g., database connection)
			loginType = "auth0" // Or some other default/indicator
			actualUserID = fullUserID
			log.Printf("[AdminHandler] User ID format does not contain '|', using full ID '%s' as actual ID and type '%s'", actualUserID, loginType)
		}
		log.Printf("[AdminHandler] Extracted Actual User ID: %s, Login Type: %s", actualUserID, loginType)
		// --- End Extract Actual ID ---

		// --- Permission Authorization Check (using Management API) ---
		// Use the fullUserID (sub claim) when checking permissions with Auth0
		hasPermission, err := checkUserPermission(r.Context(), fullUserID, requiredAdminPermission)
		if err != nil {
			log.Printf("[AdminHandler] Error checking permission '%s' for user %s: %v", requiredAdminPermission, fullUserID, err)
			http.Error(w, "Failed to verify permissions", http.StatusInternalServerError)
			return
		}

		if !hasPermission {
			log.Printf("[AdminHandler] Authorization Failed: User %s lacks '%s' permission (checked via Management API).", fullUserID, requiredAdminPermission)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(APIResponse{Message: fmt.Sprintf("Permission denied: Requires '%s' permission", requiredAdminPermission)})
			return
		}

		log.Printf("[AdminHandler] Authorization Succeeded: User %s has '%s' permission (checked via Management API).", fullUserID, requiredAdminPermission)
		// --- End Permission Authorization Check ---

		// 1. Extract the Access Token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("[AdminHandler] Error: Authorization header missing")
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		parts = strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			log.Println("[AdminHandler] Error: Authorization header format must be Bearer {token}")
			http.Error(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
			return
		}
		accessToken := parts[1]
		log.Printf("[AdminHandler] Extracted Access Token (first 10 chars): %s...", accessToken[:min(10, len(accessToken))])

		// 2. Call the /userinfo endpoint
		userInfoURL := "https://" + os.Getenv("AUTH0_DOMAIN") + "/userinfo"
		req, err := http.NewRequestWithContext(r.Context(), "GET", userInfoURL, nil)
		if err != nil {
			log.Printf("[AdminHandler] Error creating UserInfo request: %v", err)
			http.Error(w, "Failed to create request to UserInfo endpoint", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")

		log.Printf("[AdminHandler] Calling UserInfo endpoint: %s", userInfoURL)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[AdminHandler] Error calling UserInfo endpoint: %v", err)
			http.Error(w, "Failed to call UserInfo endpoint", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close() // Ensure body is closed regardless of status

		if resp.StatusCode != http.StatusOK {
			// Read the response body for more details
			bodyBytes, readErr := io.ReadAll(resp.Body)
			bodyString := ""
			if readErr != nil {
				log.Printf("[AdminHandler] Error reading UserInfo error response body: %v", readErr)
				bodyString = "(could not read error body)"
			} else {
				bodyString = string(bodyBytes)
			}

			// Log the status code and the response body
			log.Printf("[AdminHandler] Error from UserInfo endpoint: Status %d, Body: %s", resp.StatusCode, bodyString)

			// Return a more informative error (but avoid leaking sensitive details if bodyString contains them)
			http.Error(w, fmt.Sprintf("Failed to get user info: Status %d - %s", resp.StatusCode, bodyString), resp.StatusCode) // Forward the status and body
			return
		}

		// 3. Decode the UserInfo response
		var userInfo UserInfo
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			log.Printf("[AdminHandler] Error decoding UserInfo response: %v", err)
			http.Error(w, "Failed to decode user info response", http.StatusInternalServerError)
			return
		}
		log.Printf("[AdminHandler] UserInfo received: %+v", userInfo)

		// --- Database Interaction ---
		// Use the actualUserID for database operations
		userEmail := userInfo.Email
		userDisplayName := userInfo.Nickname
		userFirstName := userInfo.GivenName
		userLastName := userInfo.FamilyName

		log.Printf("[AdminHandler] Preparing DB interaction for Actual User ID: %s, Login Type: %s, Email: %s, Display Name: %s, First Name: %s, Last Name: %s",
			actualUserID, loginType, userEmail, userDisplayName, userFirstName, userLastName)

		// Check if user exists using actualUserID
		var exists bool
		checkQuery := "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)"
		err = db.QueryRowContext(r.Context(), checkQuery, actualUserID).Scan(&exists) // <<< Use actualUserID
		if err != nil {
			log.Printf("[AdminHandler] Error checking user existence for actual ID %s: %v", actualUserID, err)
			http.Error(w, "Database error checking user", http.StatusInternalServerError)
			return
		}

		if !exists {
			log.Printf("[AdminHandler] User with actual ID %s does not exist. Inserting...", actualUserID)
			// Insert user if they don't exist using actualUserID
			insertQuery := `
                INSERT INTO users (id, login_type, email, display_name, first_name, last_name)
                VALUES ($1, $2, $3, $4, $5, $6)
            `
			_, err = db.ExecContext(r.Context(), insertQuery, actualUserID, loginType, userEmail, userDisplayName, userFirstName, userLastName) // <<< Use =
			if err != nil {
				log.Printf("[AdminHandler] Error inserting user with actual ID %s: %v", actualUserID, err)
				http.Error(w, "Database error inserting user", http.StatusInternalServerError)
				return
			}
			log.Printf("[AdminHandler] User with actual ID %s inserted successfully.", actualUserID)
		} else {
			log.Printf("[AdminHandler] User with actual ID %s already exists.", actualUserID)
			// Optionally, update user details here if needed
		}
		// --- End Database Interaction ---

		// 4. Use UserInfo data (e.g., nickname) in the response
		nameToUse := userDisplayName // Use the name already processed for DB
		if nameToUse == "" {
			// Add fallbacks if nickname might be empty but other fields exist
			if userInfo.Name != "" {
				nameToUse = userInfo.Name
			} else if userInfo.Email != "" {
				nameToUse = userInfo.Email
			} else {
				nameToUse = "user" // Final fallback
			}
			log.Printf("[AdminHandler] Nickname empty, using fallback '%s' for response", nameToUse)
		}

		response := APIResponse{
			Message: fmt.Sprintf("welcome %s", nameToUse),
		}

		w.Header().Set("Content-Type", "application/json")
		log.Printf("[AdminHandler] Sending response: %+v", response)
		json.NewEncoder(w).Encode(response)
	})

	// Create the custom auth middleware instance
	authCheckMiddleware := ensureValidToken(jwtValidator, errorHandler)

	// Apply middleware chain: logging -> custom auth check -> admin handler
	protectedHandler := loggingMiddleware(authCheckMiddleware(adminHandler))
	mux.Handle("/api/v1/admin", protectedHandler)
	log.Println("Logging, Custom Auth Check, and Permission Check applied to /api/v1/admin") // Updated log

	// Add a health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[HealthHandler] Received request: %s %s", r.Method, r.URL.Path) // Added log
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := APIResponse{Message: "healthy"}
		log.Printf("[HealthHandler] Sending response: %+v", response) // Added log
		json.NewEncoder(w).Encode(response)
	})
	log.Println("Health check endpoint /health registered.") // Added log

	// Add CORS middleware
	corsMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[CORS] Request received: %s %s from Origin: %s", r.Method, r.URL.Path, r.Header.Get("Origin")) // Added log
			origin := r.Header.Get("Origin")
			allowedOrigins := []string{"http://localhost:5173", "http://127.0.0.1:5173"} // Add your frontend dev URL
			isAllowed := false
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					isAllowed = true
					break
				}
			}
			if isAllowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				log.Printf("[CORS] Allowed origin: %s", origin) // Added log
			} else {
				log.Printf("[CORS] Denied origin: %s", origin) // Added log
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")          // Allow necessary methods
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type") // Allow necessary headers
			w.Header().Set("Access-Control-Allow-Credentials", "true")                    // If needed

			if r.Method == "OPTIONS" {
				log.Println("[CORS] Handling preflight request") // Added log
				w.WriteHeader(http.StatusOK)
				return
			}

			log.Println("[CORS] Passing request to next handler") // Added log
			next.ServeHTTP(w, r)
		})
	}
	log.Println("CORS Middleware defined.") // Added log

	// Wrap the router with the CORS middleware
	wrappedRouter := corsMiddleware(mux)
	log.Println("Router wrapped with CORS middleware.") // Added log

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("Resolved port: %s", port) // Added log

	// Set up the server (remove the jwtmiddleware.Handler wrapper)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: wrappedRouter, // Use the CORS-wrapped router directly
	}

	log.Printf("Starting server on port %s...\n", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v\n", port, err)
	}

} // End of main

// Helper function to prevent panic on short strings
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
