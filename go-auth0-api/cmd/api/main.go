package main

import (
	"log"
	"net/http"

	"github.com/alessandromr/go-auth0-api/internal/auth"
	"github.com/alessandromr/go-auth0-api/internal/config"
	"github.com/alessandromr/go-auth0-api/internal/database"
	"github.com/alessandromr/go-auth0-api/internal/handler"
	"github.com/alessandromr/go-auth0-api/internal/middleware"
	_ "github.com/lib/pq" // PostgreSQL driver
)

func main() {
	log.Println("Starting Go API server...")

	// 1. Load Configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// 2. Initialize Database Connection
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
		log.Println("Database connection closed.")
	}()

	// 3. Initialize Auth0 JWT Validator
	jwtValidator, err := auth.NewValidator(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize JWT validator: %v", err)
	}

	// 4. Initialize Auth0 Management API Client
	mgmtAPI := auth.NewManagementAPI(cfg)

	// 5. Initialize API Handlers
	apiHandler := handler.NewAPIHandler(db, cfg, mgmtAPI)

	// 6. Set up Router and Middleware
	mux := http.NewServeMux()

	// Public endpoint
	mux.HandleFunc("/health", apiHandler.Health)
	log.Println("Registered public endpoint: /health")

	// Protected endpoint
	authCheckMiddleware := middleware.EnsureValidToken(jwtValidator)
	protectedAdminHandler := middleware.Logging(authCheckMiddleware(http.HandlerFunc(apiHandler.Admin)))
	mux.Handle("/api/v1/admin", protectedAdminHandler)
	log.Println("Registered protected endpoint: /api/v1/admin with Logging and Auth middleware")

	// Apply global middleware (CORS first, then Logging if desired globally, though Logging is applied per-route here)
	wrappedRouter := middleware.CORS(mux)
	log.Println("Applied CORS middleware globally")

	// 7. Start HTTP Server
	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: wrappedRouter, // Use the CORS-wrapped router
		// Add timeouts for production readiness (ReadTimeout, WriteTimeout, IdleTimeout)
	}

	log.Printf("Server starting on port %s...", cfg.Port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v", cfg.Port, err)
	}

	log.Println("Server stopped gracefully.")
}
