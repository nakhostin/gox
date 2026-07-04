package opaque

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/nakhostin/gox/session/token"
)

type Config struct {
	Secret []byte
}

type Provider struct {
	cfg Config
}

type payload struct {
	Subject   string         `json:"sub"`
	SessionID string         `json:"sid"`
	TokenID   string         `json:"jti"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp"`
	Values    map[string]any `json:"values,omitempty"`
}

func New(cfg Config) *Provider {
	return &Provider{cfg: cfg}
}

func (p *Provider) Kind() string {
	return "opaque"
}

func (p *Provider) Issue(_ context.Context, input token.IssueInput) (string, error) {
	body, err := json.Marshal(payload{
		Subject:   input.Subject,
		SessionID: input.SessionID,
		TokenID:   input.TokenID,
		IssuedAt:  input.IssuedAt.Unix(),
		ExpiresAt: input.ExpiresAt.Unix(),
		Values:    input.Values,
	})
	if err != nil {
		return "", err
	}

	bodyPart := base64.RawURLEncoding.EncodeToString(body)
	signature := sign(p.cfg.Secret, bodyPart)
	return bodyPart + "." + signature, nil
}

func (p *Provider) Validate(_ context.Context, raw string) (token.Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return token.Claims{}, token.ErrInvalidToken
	}
	if !hmac.Equal([]byte(sign(p.cfg.Secret, parts[0])), []byte(parts[1])) {
		return token.Claims{}, token.ErrInvalidToken
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return token.Claims{}, token.ErrInvalidToken
	}

	var body payload
	if err := json.Unmarshal(decoded, &body); err != nil {
		return token.Claims{}, token.ErrInvalidToken
	}
	if time.Now().UTC().After(time.Unix(body.ExpiresAt, 0).UTC()) {
		return token.Claims{}, token.ErrExpiredToken
	}

	return token.Claims{
		Subject:   body.Subject,
		SessionID: body.SessionID,
		TokenID:   body.TokenID,
		IssuedAt:  time.Unix(body.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(body.ExpiresAt, 0).UTC(),
		Values:    body.Values,
	}, nil
}

func sign(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
