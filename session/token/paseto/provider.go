package paseto

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nakhostin/gox/session/token"
	paseto "github.com/o1egl/paseto"
)

type Config struct {
	SymmetricKey []byte
	Issuer       string
	Footer       string
}

type Provider struct {
	cfg Config
	v2  *paseto.V2
}

func New(cfg Config) *Provider {
	return &Provider{
		cfg: cfg,
		v2:  paseto.NewV2(),
	}
}

func (p *Provider) Kind() string {
	return "paseto"
}

func (p *Provider) Issue(_ context.Context, input token.IssueInput) (string, error) {
	payload := paseto.JSONToken{
		Issuer:     p.cfg.Issuer,
		Subject:    input.Subject,
		Jti:        input.TokenID,
		IssuedAt:   input.IssuedAt,
		Expiration: input.ExpiresAt,
	}
	payload.Set("sid", input.SessionID)
	if len(input.Values) > 0 {
		valuesJSON, err := json.Marshal(input.Values)
		if err != nil {
			return "", err
		}
		payload.Set("vals", string(valuesJSON))
	}

	return p.v2.Encrypt(p.cfg.SymmetricKey, payload, p.cfg.Footer)
}

func (p *Provider) Validate(_ context.Context, raw string) (token.Claims, error) {
	var parsed paseto.JSONToken
	var footer string
	if err := p.v2.Decrypt(raw, p.cfg.SymmetricKey, &parsed, &footer); err != nil {
		return token.Claims{}, token.ErrInvalidToken
	}
	if p.cfg.Footer != "" && footer != p.cfg.Footer {
		return token.Claims{}, token.ErrInvalidToken
	}
	if err := parsed.Validate(); err != nil {
		return token.Claims{}, token.ErrExpiredToken
	}
	if time.Now().UTC().After(parsed.Expiration) {
		return token.Claims{}, token.ErrExpiredToken
	}

	sessionID := parsed.Get("sid")
	if sessionID == "" {
		return token.Claims{}, token.ErrInvalidToken
	}
	tokenID := parsed.Jti
	if tokenID == "" {
		return token.Claims{}, token.ErrInvalidToken
	}

	values := map[string]any(nil)
	if rawValues := parsed.Get("vals"); rawValues != "" {
		values = map[string]any{}
		if err := json.Unmarshal([]byte(rawValues), &values); err != nil {
			return token.Claims{}, token.ErrInvalidToken
		}
	}

	return token.Claims{
		Subject:   parsed.Subject,
		SessionID: sessionID,
		TokenID:   tokenID,
		IssuedAt:  parsed.IssuedAt.UTC(),
		ExpiresAt: parsed.Expiration.UTC(),
		Values:    values,
	}, nil
}
