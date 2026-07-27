package errors

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token has expired")
	ErrTokenNotFound      = errors.New("token not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrClientNotFound     = errors.New("client not found")
	ErrInvalidClient      = errors.New("invalid client credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")

	// Token errors
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	ErrRefreshTokenInvalid = errors.New("invalid refresh token")
	ErrTokenGeneration     = errors.New("failed to generate token")

	// Client errors
	ErrClientAlreadyExists = errors.New("client already exists")
	ErrInvalidRedirectURI  = errors.New("invalid redirect URI")
	ErrInvalidGrantType    = errors.New("invalid grant type")

	// User provider errors
	ErrUserProviderNotFound = errors.New("user provider not found")
	ErrInvalidUserProvider  = errors.New("invalid user provider")
)

// AuthError represents a structured authentication error
type AuthError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func (e *AuthError) Error() string {
	return e.Message
}

func NewAuthError(code, message string, details map[string]interface{}) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Details: details,
	}
}
