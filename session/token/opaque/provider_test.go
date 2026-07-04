package opaque

import (
	"context"
	"testing"
	"time"

	"github.com/nakhostin/gox/session/token"
)

func TestProviderIssueAndValidate(t *testing.T) {
	provider := New(Config{
		Secret: []byte("opaque-secret"),
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
		t.Fatalf("issue opaque token: %v", err)
	}

	claims, err := provider.Validate(context.Background(), raw)
	if err != nil {
		t.Fatalf("validate opaque token: %v", err)
	}
	if claims.Values["role"] != "admin" {
		t.Fatalf("unexpected custom claims: %+v", claims.Values)
	}
}
