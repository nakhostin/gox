package jwt

import (
	"context"
	"errors"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/nakhostin/gox/session/token"
)

type Config struct {
	Secret   []byte
	Issuer   string
	Audience []string
}

type Provider struct {
	cfg Config
}

func New(cfg Config) *Provider {
	return &Provider{cfg: cfg}
}

func (p *Provider) Kind() string {
	return "jwt"
}

func (p *Provider) Issue(_ context.Context, input token.IssueInput) (string, error) {
	claims := jwtv5.MapClaims{
		"sub": input.Subject,
		"sid": input.SessionID,
		"jti": input.TokenID,
		"iat": input.IssuedAt.Unix(),
		"exp": input.ExpiresAt.Unix(),
	}

	if p.cfg.Issuer != "" {
		claims["iss"] = p.cfg.Issuer
	}
	if len(p.cfg.Audience) > 0 {
		claims["aud"] = p.cfg.Audience
	}
	for key, value := range input.Values {
		claims[key] = value
	}

	raw := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	return raw.SignedString(p.cfg.Secret)
}

func (p *Provider) Validate(_ context.Context, raw string) (token.Claims, error) {
	parsed, err := jwtv5.Parse(raw, func(t *jwtv5.Token) (any, error) {
		if t.Method != jwtv5.SigningMethodHS256 {
			return nil, token.ErrInvalidToken
		}
		return p.cfg.Secret, nil
	})
	if err != nil {
		if errors.Is(err, jwtv5.ErrTokenExpired) {
			return token.Claims{}, token.ErrExpiredToken
		}
		return token.Claims{}, token.ErrInvalidToken
	}

	mapClaims, ok := parsed.Claims.(jwtv5.MapClaims)
	if !ok || !parsed.Valid {
		return token.Claims{}, token.ErrInvalidToken
	}

	claims, err := mapToClaims(mapClaims)
	if err != nil {
		return token.Claims{}, err
	}

	return claims, nil
}

func mapToClaims(claims jwtv5.MapClaims) (token.Claims, error) {
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return token.Claims{}, token.ErrInvalidToken
	}
	sessionID, ok := claims["sid"].(string)
	if !ok || sessionID == "" {
		return token.Claims{}, token.ErrInvalidToken
	}
	tokenID, ok := claims["jti"].(string)
	if !ok || tokenID == "" {
		return token.Claims{}, token.ErrInvalidToken
	}

	issuedAtUnix, ok := claims["iat"].(float64)
	if !ok {
		return token.Claims{}, token.ErrInvalidToken
	}
	expiresAtUnix, ok := claims["exp"].(float64)
	if !ok {
		return token.Claims{}, token.ErrInvalidToken
	}

	values := make(map[string]any, len(claims))
	for key, value := range claims {
		switch key {
		case "sub", "sid", "jti", "iat", "exp", "iss", "aud":
			continue
		default:
			values[key] = value
		}
	}

	return token.Claims{
		Subject:   subject,
		SessionID: sessionID,
		TokenID:   tokenID,
		IssuedAt:  time.Unix(int64(issuedAtUnix), 0).UTC(),
		ExpiresAt: time.Unix(int64(expiresAtUnix), 0).UTC(),
		Values:    values,
	}, nil
}
