// filepath: /Users/alessandro/repos/labs/projects/vite/auth0-demo-app/go-auth0-api/internal/middleware/middleware.go
package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/alessandromr/go-auth0-api/internal/auth"   // Adjust import path
	"github.com/alessandromr/go-auth0-api/internal/models" // Adjust import path
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
)

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

// Logging logs incoming requests
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[Logging] Started %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		wrapper := &responseWriterWrapper{ResponseWriter: w}

		next.ServeHTTP(wrapper, r)

		log.Printf(
			"[Logging] Completed %s %s in %v with status %d",
			r.Method,
			r.URL.Path,
			time.Since(start),
			wrapper.status,
		)
	})
}

// CORS handles Cross-Origin Resource Sharing headers
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[CORS] Request received: %s %s from Origin: %s", r.Method, r.URL.Path, r.Header.Get("Origin"))
		origin := r.Header.Get("Origin")
		// TODO: Make allowed origins configurable
		allowedOrigins := []string{"http://localhost:5173", "http://127.0.0.1:5173"}
		isAllowed := false
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				isAllowed = true
				break
			}
		}
		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			log.Printf("[CORS] Allowed origin: %s", origin)
		} else if origin != "" { // Only log denial if an origin was actually sent
			log.Printf("[CORS] Denied origin: %s", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			log.Println("[CORS] Handling preflight request")
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Println("[CORS] Passing request to next handler")
		next.ServeHTTP(w, r)
	})
}

// AuthErrorHandler handles errors from the JWT validation middleware.
func AuthErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("[AuthErrorHandler] Responding to auth failure. Error: %v", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(models.APIResponse{Message: "Authentication failed: " + err.Error()})
}

// EnsureValidToken creates the JWT validation middleware.
func EnsureValidToken(val *auth.Validator) func(http.Handler) http.Handler {
	middleware := jwtmiddleware.New(val.ValidateToken, jwtmiddleware.WithErrorHandler(AuthErrorHandler))

	return func(next http.Handler) http.Handler {
		return middleware.CheckJWT(next)
	}
}
