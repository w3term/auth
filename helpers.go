package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Global config cache with thread safety
var (
	githubConfig *GitHubConfig
	configMutex  sync.RWMutex
	configLoaded bool
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

// Auth helper

// Checks if a user is a member of the specified GitHub organization
func isUserInOrganization(accessToken string, username string, orgName string) (bool, error) {
	log.Printf("Checking if %s is a member of organization %s", username, orgName)

	// Check if user is in the organization
	orgCheckURL := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", orgName, username)

	req, err := http.NewRequest("GET", orgCheckURL, nil)
	if err != nil {
		return false, err
	}

	// Important: Add the Authorization header with the OAuth token
	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making GitHub API request: %v", err)
		return false, err
	}
	defer resp.Body.Close()

	log.Printf("GitHub API response: %d %s", resp.StatusCode, resp.Status)

	// For debugging, dump response headers
	/*log.Printf("Response headers:")
	for name, values := range resp.Header {
		log.Printf("  %s: %v", name, values)
	}*/

	// Status 204 No Content means the user is a member
	if resp.StatusCode == 204 {
		log.Printf("User %s is a member of organization %s", username, orgName)
		return true, nil
	} else if resp.StatusCode == 404 {
		log.Printf("User %s is NOT a member of organization %s", username, orgName)
		return false, nil
	} else {
		// Read and log the response body for other status codes
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Unexpected API response: %s", string(body))
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// Extract GitHub application name from state
func extractAppFromState(state string) string {
	parts := strings.Split(state, "_")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return ""
}

// Load GitHub configuration from file
func loadGitHubConfig() (*GitHubConfig, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	// Return cached config if already loaded
	if configLoaded && githubConfig != nil {
		return githubConfig, nil
	}

	configPath := os.Getenv("GITHUB_CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/config/github-apps.yaml"
	}

	log.Printf("Loading GitHub configuration from: %s", configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config GitHubConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %v", err)
	}

	// Validate configuration
	if len(config.GitHubApplications) == 0 {
		return nil, fmt.Errorf("no GitHub applications configured")
	}

	githubConfig = &config
	configLoaded = true

	log.Printf("Successfully loaded GitHub configuration with %d applications:", len(config.GitHubApplications))
	for appName := range config.GitHubApplications {
		log.Printf("  - %s", appName)
	}

	return githubConfig, nil
}

// Get GitHub app configuration by name
func getGitHubAppConfig(appName string) (*GitHubApp, error) {
	// Load config if not already loaded
	config, err := loadGitHubConfig()
	if err != nil {
		return nil, err
	}

	configMutex.RLock()
	defer configMutex.RUnlock()

	if app, exists := config.GitHubApplications[appName]; exists {
		return &app, nil
	}

	return nil, fmt.Errorf("GitHub application '%s' not found in configuration", appName)
}

// Generic helpers

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
