package main

import (
	"github.com/dgrijalva/jwt-go"
)

type GitHubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type ValidationResponse struct {
	Valid bool       `json:"valid"`
	User  *jwt.Token `json:"user,omitempty"`
	Error string     `json:"error,omitempty"`
}
