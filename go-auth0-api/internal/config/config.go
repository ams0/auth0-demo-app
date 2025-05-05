// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/config/config.go
package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application.
type Config struct {
	Port                    string
	Auth0Domain             string
	Auth0Audiences          []string
	Auth0MgmtClientID       string
	Auth0MgmtClientSecret   string
	DBHost                  string
	DBPort                  string
	DBUser                  string
	DBPassword              string
	DBName                  string
	DBSSLMode               string
	RequiredAdminPermission string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg := &Config{
		Port:                    getEnv("PORT", "3000"),
		Auth0Domain:             getEnvOrFatal("AUTH0_DOMAIN"),
		Auth0MgmtClientID:       getEnvOrFatal("AUTH0_MANAGEMENT_CLIENT_ID"),
		Auth0MgmtClientSecret:   getEnvOrFatal("AUTH0_MANAGEMENT_CLIENT_SECRET"),
		DBHost:                  getEnvOrFatal("DB_HOST"),
		DBPort:                  getEnvOrFatal("DB_PORT"),
		DBUser:                  getEnvOrFatal("DB_USER"),
		DBPassword:              getEnvOrFatal("DB_PASSWORD"),
		DBName:                  getEnvOrFatal("DB_NAME"),
		DBSSLMode:               getEnv("DB_SSLMODE", "disable"),
		RequiredAdminPermission: getEnv("REQUIRED_ADMIN_PERMISSION", "all-users"), // Default permission
	}

	audiencesStr := getEnvOrFatal("AUTH0_AUDIENCES")
	cfg.Auth0Audiences = parseAudiences(audiencesStr)

	log.Printf("Loaded configuration: Port=%s, Domain=%s, Audiences=%v, DBHost=%s, DBPort=%s, DBName=%s",
		cfg.Port, cfg.Auth0Domain, cfg.Auth0Audiences, cfg.DBHost, cfg.DBPort, cfg.DBName)

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// getEnvOrFatal retrieves an environment variable or logs a fatal error if not set.
func getEnvOrFatal(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("FATAL: Environment variable %s must be set", key)
	}
	return value
}

// parseAudiences splits and trims a comma-separated audience string.
func parseAudiences(audiencesStr string) []string {
	audiences := strings.Split(audiencesStr, ",")
	for i := range audiences {
		audiences[i] = strings.TrimSpace(audiences[i])
	}
	log.Printf("Parsed Audiences: %v", audiences)
	return audiences
}

// GetDBConnectionString constructs the database connection string from config.
func (c *Config) GetDBConnectionString() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName, c.DBSSLMode)
}
