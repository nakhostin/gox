package token

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidToken = errors.New("token: invalid token")
	ErrExpiredToken = errors.New("token: expired token")
)

type Claims struct {
	Subject   string
	SessionID string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Values    map[string]any
}

type IssueInput struct {
	Subject   string
	SessionID string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Values    map[string]any
}

type Provider interface {
	Kind() string
	Issue(ctx context.Context, input IssueInput) (string, error)
	Validate(ctx context.Context, raw string) (Claims, error)
}
