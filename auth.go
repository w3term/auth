package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type GitHubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type ValidationResponse struct {
	Valid bool       `json:"valid"`
	User  *jwt.Token `json:"user,omitempty"`
	Error string     `json:"error,omitempty"`
}

func main() {
	router := mux.NewRouter()

	// GitHub OAuth endpoints
	router.HandleFunc("/auth/github/login", handleGitHubLogin).Methods("GET")
	router.HandleFunc("/auth/github/callback", handleGitHubCallback).Methods("GET")

	// Token validation endpoint
	router.HandleFunc("/validate-token", validateToken).Methods("POST")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("Auth service running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	redirectURI := os.Getenv("GITHUB_CALLBACK_URL")

	authURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		clientID, redirectURI,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code parameter is required", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "Failed to parse token response", http.StatusInternalServerError)
		return
	}

	// Get user info from GitHub
	userReq, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		http.Error(w, "Failed to create user request", http.StatusInternalServerError)
		return
	}

	userReq.Header.Set("Authorization", "token "+tokenResp.AccessToken)

	userResp, err := client.Do(userReq)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	userData, err := ioutil.ReadAll(userResp.Body)
	if err != nil {
		http.Error(w, "Failed to read user data", http.StatusInternalServerError)
		return
	}

	var githubUser GitHubUser
	if err := json.Unmarshal(userData, &githubUser); err != nil {
		http.Error(w, "Failed to parse user data", http.StatusInternalServerError)
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"githubId": githubUser.ID,
		"username": githubUser.Login,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
		"issuedAt": time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenString,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600, // 1 hour
		Path:     "/",
	})

	// Redirect back to the Hugo site
	http.Redirect(w, r, os.Getenv("HUGO_SITE_URL")+"/terminal", http.StatusTemporaryRedirect)
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
		json.NewEncoder(w).Encode(ValidationResponse{
			Valid: true,
			User:  parsedToken,
		})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ValidationResponse{
			Valid: false,
			Error: "Invalid token",
		})
	}
}
