// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/database/database.go
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/alessandromr/go-auth0-api/internal/config" // Adjust import path if needed
	"github.com/alessandromr/go-auth0-api/internal/models" // Adjust import path if needed
	_ "github.com/lib/pq"                                  // PostgreSQL driver
)

// DB holds the database connection pool.
type DB struct {
	*sql.DB
}

// NewConnection creates and returns a new database connection pool.
func NewConnection(cfg *config.Config) (*DB, error) {
	connStr := cfg.GetDBConnectionString()
	log.Println("Attempting to connect to database...")

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Check if the connection is actually established
	err = db.Ping()
	if err != nil {
		db.Close() // Close the connection if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Successfully connected to PostgreSQL database.")
	return &DB{db}, nil
}

// CheckAndInsertUser checks if a user exists by their actual ID and inserts them if not.
func (db *DB) CheckAndInsertUser(ctx context.Context, actualUserID, loginType string, userInfo *models.UserInfo) error {
	log.Printf("[DB] Preparing DB interaction for Actual User ID: %s, Login Type: %s, Email: %s",
		actualUserID, loginType, userInfo.Email)

	// Check if user exists using actualUserID
	var exists bool
	checkQuery := "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)"
	err := db.QueryRowContext(ctx, checkQuery, actualUserID).Scan(&exists)
	if err != nil {
		log.Printf("[DB] Error checking user existence for actual ID %s: %v", actualUserID, err)
		return fmt.Errorf("database error checking user: %w", err)
	}

	if !exists {
		log.Printf("[DB] User with actual ID %s does not exist. Inserting...", actualUserID)
		// Insert user if they don't exist using actualUserID
		insertQuery := `
            INSERT INTO users (id, login_type, email, display_name, first_name, last_name)
            VALUES ($1, $2, $3, $4, $5, $6)
        `
		_, err = db.ExecContext(ctx, insertQuery,
			actualUserID,
			loginType,
			userInfo.Email,
			userInfo.Nickname, // Use Nickname as display_name
			userInfo.GivenName,
			userInfo.FamilyName,
		)
		if err != nil {
			log.Printf("[DB] Error inserting user with actual ID %s: %v", actualUserID, err)
			return fmt.Errorf("database error inserting user: %w", err)
		}
		log.Printf("[DB] User with actual ID %s inserted successfully.", actualUserID)
	} else {
		log.Printf("[DB] User with actual ID %s already exists.", actualUserID)
		// Optionally, add logic here to update user details if they already exist
	}
	return nil
}
