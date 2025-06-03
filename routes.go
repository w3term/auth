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
	"time"

	"github.com/dgrijalva/jwt-go"
)

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {

	// Log incoming request details
	/* for k, v := range r.Header { log.Printf("Incoming request header %s: %v", k, v) }*/
	log.Printf("Client IP: %s", r.RemoteAddr)
	log.Printf("User Agent: %s", r.UserAgent())
	log.Printf("Incoming GitHub Callback Request:")
	log.Printf("Full URL: %s", r.URL.String())
	log.Printf("Query Parameters: %v", r.URL.Query())

	// Make sure code is provided
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code parameter is required", http.StatusBadRequest)
		return
	}

	// Make sure state is provided
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "Code and state parameters are required", http.StatusBadRequest)
		return
	}
	log.Printf("state was provided: %s", state)

	// Extract GitHub Application name from state
	gitHubAppName := extractAppFromState(state)
	if gitHubAppName == "" {
		log.Printf("Could not extract GitHub App name from state: %s", state)
		http.Error(w, "Invalid state format", http.StatusBadRequest)
		return
	}
	log.Printf("Processing callback for GitHub app: %s", gitHubAppName)

	// Get the GitHub app config for this app name
	githubApp, err := getGitHubAppConfig(gitHubAppName)
	if err != nil {
		log.Printf("Error getting GitHub app config: %v", err)
		http.Error(w, "Invalid application configuration", http.StatusInternalServerError)
		return
	}

	// Define webSiteURL, clientID and clientSecret
	webSiteURL := githubApp.WebsiteURL
	clientID := githubApp.ClientID
	clientSecret := githubApp.ClientSecret
	authorizationCallbackURL := githubApp.AuthorizationCallbackURL
	log.Printf("GithubApp: %s / %s / %s / %s", webSiteURL, clientID, clientSecret[:min(5, len(clientSecret))], authorizationCallbackURL)

	// Exchange code for access token
	requestBody, _ := json.Marshal(map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	})

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Printf("Error creating token exchange request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error exchanging code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading token response: %v", err)
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	log.Printf("GitHub token response status: %d", resp.StatusCode)
	//log.Printf("GitHub token response headers: %+v", resp.Header)
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

	// Check if access token is empty
	if tokenResp.AccessToken == "" {
		log.Printf("Received empty access token from GitHub")
		log.Printf("GitHub response body: %s", string(body))
		http.Error(w, "GitHub returned empty access token", http.StatusInternalServerError)
		return
	}

	log.Printf("Received access token from GitHub: %s...", tokenResp.AccessToken[:min(10, len(tokenResp.AccessToken))])
	log.Printf("Scope is %s", tokenResp.Scope)

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
	orgName := os.Getenv("GITHUB_ORG_NAME")
	if orgName != "" {
		isOrgMember, err := isUserInOrganization(tokenResp.AccessToken, githubUser.Login, orgName)
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
	} else {
		log.Printf("GITHUB_ORG_NAME not provided. No organization check will be done => user authorized.")
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"githubId": githubUser.ID,
		"username": githubUser.Login,
		"app":      gitHubAppName,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"issuedAt": time.Now().Unix(),
	})

	log.Printf("Creating JWT with claims - githubId: %d, username: %s, app: %s",
		githubUser.ID, githubUser.Login, gitHubAppName)

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		log.Printf("Error signing JWT token: %v", err)
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

	// Validate redirect URL
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		log.Printf("Error parsing redirect URL: %v", err)
		http.Error(w, "Failed to construct redirect", http.StatusInternalServerError)
		return
	}

	log.Printf("Parsed URL: %v", parsedURL)

	// Standard redirect
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)

	// If that doesn't work, try manual header setting
	//w.Header().Set("Location", redirectURL)
	//w.WriteHeader(http.StatusTemporaryRedirect)
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
