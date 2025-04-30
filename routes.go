package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	redirectURI := os.Getenv("GITHUB_CALLBACK_URL")
	log.Printf("Using callback URL: %s", redirectURI)

	authURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=read:user,read:org",
		clientID, redirectURI,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {

	log.Printf("Incoming Request Headers:")
	for k, v := range r.Header {
		log.Printf("%s: %v", k, v)
	}

	log.Printf("Client IP: %s", r.RemoteAddr)
	log.Printf("User Agent: %s", r.UserAgent())

	// Log all incoming request details
	log.Printf("Incoming GitHub Callback Request:")
	log.Printf("Full URL: %s", r.URL.String())
	log.Printf("Query Parameters: %v", r.URL.Query())

	// Log environment variables
	webSiteURL := os.Getenv("WEBSITE_URL")
	log.Printf("WEBSITE_URL: %s", webSiteURL)

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code parameter is required", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	log.Printf("Using GitHub OAuth credentials - Client ID: %s, Secret: %s...",
		clientID, clientSecret[:min(5, len(clientSecret))])

	requestBody, _ := json.Marshal(map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	})

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestBody))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	log.Printf("GitHub token response status: %d", resp.StatusCode)
	log.Printf("GitHub token response headers: %+v", resp.Header)
	log.Printf("GitHub token response body: %s", string(body))

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("Failed to parse token response: %v", err)
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Log the token response
	if len(tokenResp.AccessToken) > 10 {
		maskedToken := tokenResp.AccessToken[:5] + "..." + tokenResp.AccessToken[len(tokenResp.AccessToken)-5:]
		log.Printf("Token response: token=%s, scope=%s, type=%s",
			maskedToken, tokenResp.Scope, tokenResp.TokenType)
	} else {
		log.Printf("Warning: Received unexpectedly short access token")
	}

	// Check if the token includes the read:org scope
	if tokenResp.Scope == "" {
		log.Printf("Warning: No scope information in token response")
	} else if !strings.Contains(tokenResp.Scope, "read:org") {
		log.Printf("Warning: Access token does not have read:org scope, organization check may fail")
	}

	// Check if access token is empty
	if tokenResp.AccessToken == "" {
		log.Printf("Received empty access token from GitHub")
		log.Printf("GitHub response body: %s", string(body))
		http.Error(w, "GitHub returned empty access token", http.StatusInternalServerError)
		return
	}

	log.Printf("Received access token from GitHub: %s...", tokenResp.AccessToken[:min(10, len(tokenResp.AccessToken))])
	log.Printf("Scope is %s", tokenResp.Scope)

	// Check if the token includes the read:org scope
	if !strings.Contains(tokenResp.Scope, "read:org") {
		log.Printf("Warning: Access token does not have read:org scope, organization check may fail")
	}

	// Get user info from GitHub
	userReq, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		log.Printf("Error creating user request: %v", err)
		http.Error(w, "Failed to create user request", http.StatusInternalServerError)
		return
	}

	userReq.Header.Set("Authorization", "token "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	log.Printf("Requesting GitHub user info")

	userResp, err := client.Do(userReq)
	if err != nil {
		log.Printf("Error getting user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	// Check response status
	if userResp.StatusCode != http.StatusOK {
		userData, _ := io.ReadAll(userResp.Body)
		log.Printf("GitHub API returned error status %d: %s", userResp.StatusCode, string(userData))
		http.Error(w, fmt.Sprintf("GitHub API error: %d", userResp.StatusCode), http.StatusInternalServerError)
		return
	}

	userData, err := io.ReadAll(userResp.Body)
	if err != nil {
		log.Printf("Error reading user data: %v", err)
		http.Error(w, "Failed to read user data", http.StatusInternalServerError)
		return
	}

	log.Printf("GitHub API response: %s", string(userData))

	var githubUser GitHubUser
	if err := json.Unmarshal(userData, &githubUser); err != nil {
		log.Printf("Error parsing user data: %v", err)
		log.Printf("Raw user data: %s", string(userData))
		http.Error(w, "Failed to parse user data", http.StatusInternalServerError)
		return
	}

	// Verify we have a valid user
	if githubUser.ID == 0 || githubUser.Login == "" {
		log.Printf("GitHub API returned invalid user: %+v", githubUser)
		http.Error(w, "GitHub API returned invalid user", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully retrieved GitHub user: ID=%d, Login=%s",
		githubUser.ID, githubUser.Login)

	// Check if user is in the specified organization
	isOrgMember, err := isUserInOrganization(tokenResp.AccessToken, githubUser.Login)
	if err != nil {
		log.Printf("Error checking organization membership: %v", err)
		http.Error(w, "Failed to verify organization membership", http.StatusInternalServerError)
		return
	}

	if !isOrgMember {
		log.Printf("Unauthorized user attempted login: %s (not in organization)", githubUser.Login)

		// Redirect to an unauthorized page
		http.Error(w, "User not in requested organization", http.StatusInternalServerError)
		return
	}

	log.Printf("Authorized user logged in: %s (organization member)", githubUser.Login)

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"githubId": githubUser.ID,
		"username": githubUser.Login,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"issuedAt": time.Now().Unix(),
	})

	log.Printf("Creating JWT with claims - githubId: %d, username: %s",
		githubUser.ID, githubUser.Login)

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Get cookie domain
	cookieDomain := extractCookieDomain(r.Host)
	log.Printf("Setting cookie for domain: '%s' (from host: '%s')", cookieDomain, r.Host)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		HttpOnly: false,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
		Path:     "/",
		Domain:   cookieDomain,
	})

	redirectURL := fmt.Sprintf("%s?auth_success=true&t=%d",
		webSiteURL,
		time.Now().Unix())

	log.Printf("Constructed Redirect Full URL: %s", redirectURL)

	// Try using the parsed URL
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		log.Printf("Error parsing redirect URL: %v", err)
		http.Error(w, "Failed to construct redirect", http.StatusInternalServerError)
		return
	}

	// Try multiple redirect methods
	log.Printf("Attempting redirect:")
	log.Printf("1. Full URL: %s", redirectURL)
	log.Printf("2. Parsed URL: %v", parsedURL)

	// Method 1: Standard redirect
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)

	// If that doesn't work, try manual header setting
	w.Header().Set("Location", redirectURL)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func validateToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get token from request
	var token string

	// Check if token is in request body
	if r.Body != nil {
		var data map[string]string
		if err := json.NewDecoder(r.Body).Decode(&data); err == nil {
			token = data["token"]
		}
	}

	// If not in body, check cookies
	if token == "" {
		if cookie, err := r.Cookie("auth_token"); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		json.NewEncoder(w).Encode(ValidationResponse{
			Valid: false,
			Error: "No token provided",
		})
		return
	}

	// Validate token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ValidationResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	if parsedToken.Valid {
		// Extract claims from the token to make it easier to use in the client
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ValidationResponse{
				Valid: false,
				Error: "Could not extract claims from token",
			})
			return
		}

		// Log the exact claims content
		log.Printf("Token claims: %+v", claims)

		// Create a simplified response with extracted claims
		type UserInfo struct {
			Username string `json:"username"`
			GithubID int    `json:"githubId"`
		}

		userInfo := UserInfo{
			Username: claims["username"].(string),
			GithubID: int(claims["githubId"].(float64)),
		}

		// Log the outgoing response
		log.Printf("Sending user info in response: %+v", userInfo)

		response := struct {
			Valid bool     `json:"valid"`
			User  UserInfo `json:"user"`
		}{
			Valid: true,
			User:  userInfo,
		}

		// Log the final response
		log.Printf("Full response: %+v", response)

		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ValidationResponse{
			Valid: false,
			Error: "Invalid token",
		})
	}
}
