package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	// Get the allowed origins
	allowedOrigins := getAllowedOrigins()
	log.Printf("CORS allowed origins: %v", allowedOrigins)

	// Setup router
	router := mux.NewRouter()

	// Routes
	router.HandleFunc("/auth/github/login", handleGitHubLogin).Methods("GET")
	router.HandleFunc("/auth/github/callback", handleGitHubCallback).Methods("GET")
	router.HandleFunc("/validate-token", validateToken).Methods("POST", "OPTIONS")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("Auth service running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, corsMiddleware(router)))
}
