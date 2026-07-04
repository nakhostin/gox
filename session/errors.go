package session

import "errors"

var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionInvalid       = errors.New("session is invalid")
	ErrSessionExpired       = errors.New("session expired")
	ErrSessionRevoked       = errors.New("session revoked")
	ErrSessionDisabled      = errors.New("session disabled")
	ErrRefreshTokenInvalid  = errors.New("refresh token invalid")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenReplayed = errors.New("refresh token replay detected")
	ErrAccessTokenInvalid   = errors.New("access token invalid")
	ErrAccessTokenExpired   = errors.New("access token expired")
	ErrMaxSessionsReached   = errors.New("maximum active sessions reached")
	ErrUnsupportedProvider  = errors.New("unsupported token provider")
	ErrInvalidConfiguration = errors.New("invalid session configuration")
	ErrInternal             = errors.New("internal session error")
)
