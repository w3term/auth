package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// CORS helpers

// Returns a list of origins allowed for CORS
func getAllowedOrigins() []string {
	corsOrigins := os.Getenv("ALLOWED_ORIGINS")
	if corsOrigins == "" {
		return []string{}
	}

	// Split list
	origins := strings.Split(corsOrigins, ",")
	for i, origin := range origins {
		origins[i] = strings.TrimSpace(origin)
	}

	return origins
}

// Checks if the given origin is in the allowed list
func isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	allowedOrigins := getAllowedOrigins()
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

// Create a middleware handler for CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		log.Printf("CORS request from origin: %s", origin)

		// Allow requests with no origin (treated as same-origin requests)
		if origin == "" {
			log.Printf("Empty origin - treating as same-origin request")
			next.ServeHTTP(w, r)
			return
		}

		// Only set CORS headers for allowed origins
		if isOriginAllowed(origin) {
			log.Printf("Origin allowed: %s", origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		} else {
			log.Printf("Origin rejected: %s", origin)
			log.Printf("Allowed origins: %v", getAllowedOrigins())

			// Return an error if the origin is not allowed
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Cross-origin request not allowed"))
		}
	})
}

// Cookie helpers

// Extracts cookie domain
func extractCookieDomain(host string) string {
	// For localhost, use empty domain
	if host == "localhost" || strings.HasPrefix(host, "localhost:") {
		return ""
	}

	// Remove port if present
	if colonIndex := strings.IndexByte(host, ':'); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Split the host into parts
	parts := strings.Split(host, ".")

	// If there are fewer than 3 parts (e.g., example.com), just return the host
	if len(parts) < 3 {
		return host
	}

	// Remove the first part (subdomain) and return the rest
	return strings.Join(parts[1:], ".")
}

// Generic helpers

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
