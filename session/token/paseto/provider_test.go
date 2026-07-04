package paseto

import (
	"context"
	"testing"
	"time"

	"github.com/nakhostin/gox/session/token"
)

func TestProviderIssueAndValidate(t *testing.T) {
	provider := New(Config{
		SymmetricKey: []byte("0123456789abcdef0123456789abcdef"),
		Issuer:       "gox-test",
		Footer:       "gox-footer",
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
		t.Fatalf("issue paseto token: %v", err)
	}

	claims, err := provider.Validate(context.Background(), raw)
	if err != nil {
		t.Fatalf("validate paseto token: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "session-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}
