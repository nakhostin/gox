package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/nakhostin/gox/session/token"
)

func TestProviderIssueAndValidate(t *testing.T) {
	provider := New(Config{
		Secret: []byte("jwt-secret"),
		Issuer: "gox-test",
	})

	raw, err := provider.Issue(context.Background(), token.IssueInput{
		Subject:   "user-1",
		SessionID: "session-1",
		TokenID:   "token-1",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Values: map[string]any{
			"role": "admin",
		},
	})
	if err != nil {
		t.Fatalf("issue jwt: %v", err)
	}

	claims, err := provider.Validate(context.Background(), raw)
	if err != nil {
		t.Fatalf("validate jwt: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "session-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}
