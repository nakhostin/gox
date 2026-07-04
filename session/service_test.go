package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/nakhostin/gox/session"
	"github.com/nakhostin/gox/session/config"
	"github.com/nakhostin/gox/session/store/memory"
	opaquetoken "github.com/nakhostin/gox/session/token/opaque"
)

func TestServiceCreateValidateRefresh(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)

	store := memory.New()
	provider := opaquetoken.New(opaquetoken.Config{Secret: []byte("opaque-access-secret")})
	svc := session.New(
		config.New().
			WithRefreshTokenSecret("refresh-secret").
			WithAccessTokenTTL(15*time.Minute).
			WithRefreshTokenTTL(24*time.Hour).
			WithIdleTimeout(24*time.Hour).
			WithAbsoluteTTL(7*24*time.Hour).
			Build(),
		store,
		provider,
		nil,
		session.WithNowFunc(func() time.Time { return now }),
	)

	login, err := svc.Create(ctx, session.CreateInput{
		UserID:     "user-1",
		DeviceID:   "device-1",
		DeviceName: "mac",
		Platform:   "web",
		IPAddress:  "127.0.0.1",
		UserAgent:  "test-agent",
		Claims: map[string]any{
			"role": "admin",
		},
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	claims, err := svc.ValidateAccessToken(ctx, login.AccessToken)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if claims.SessionID != login.Session.ID {
		t.Fatalf("unexpected session id: got %s want %s", claims.SessionID, login.Session.ID)
	}

	now = now.Add(2 * time.Minute)
	refreshed, err := svc.Refresh(ctx, session.RefreshInput{
		RefreshToken: login.RefreshToken,
		IPAddress:    "127.0.0.2",
		UserAgent:    "new-agent",
	})
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}
	if refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("expected refresh rotation")
	}
	if refreshed.Session.AccessTokenVersion != 2 {
		t.Fatalf("expected access token version 2, got %d", refreshed.Session.AccessTokenVersion)
	}

	history, err := svc.ListHistory(ctx, "user-1", session.HistoryQuery{})
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history) < 2 {
		t.Fatalf("expected at least 2 history events, got %d", len(history))
	}
}

func TestServiceEvictsOldestSessionWhenLimitReached(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)

	store := memory.New()
	provider := opaquetoken.New(opaquetoken.Config{Secret: []byte("opaque-access-secret")})
	svc := session.New(
		config.New().
			WithRefreshTokenSecret("refresh-secret").
			WithMaxActiveSessionsPerUser(1).
			WithMaxActiveSessionsPerDevice(1).
			WithLimitBehavior(config.LimitEvictOldest).
			Build(),
		store,
		provider,
		nil,
		session.WithNowFunc(func() time.Time { return now }),
	)

	first, err := svc.Create(ctx, session.CreateInput{
		UserID:    "user-1",
		DeviceID:  "device-1",
		IPAddress: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("create first session: %v", err)
	}

	now = now.Add(time.Second)
	second, err := svc.Create(ctx, session.CreateInput{
		UserID:    "user-1",
		DeviceID:  "device-2",
		IPAddress: "127.0.0.2",
	})
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}

	old, err := svc.Get(ctx, first.Session.ID)
	if err != nil {
		t.Fatalf("get first session: %v", err)
	}
	if old.Status != session.StatusReplaced {
		t.Fatalf("expected old session to be replaced, got %s", old.Status)
	}

	active, err := svc.ListActive(ctx, "user-1")
	if err != nil {
		t.Fatalf("list active sessions: %v", err)
	}
	if len(active) != 1 || active[0].ID != second.Session.ID {
		t.Fatalf("unexpected active sessions: %+v", active)
	}
}

func TestServiceDetectsRefreshReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)

	store := memory.New()
	provider := opaquetoken.New(opaquetoken.Config{Secret: []byte("opaque-access-secret")})
	svc := session.New(
		config.New().
			WithRefreshTokenSecret("refresh-secret").
			WithRevokeFamilyOnRefreshReplay(true).
			Build(),
		store,
		provider,
		nil,
		session.WithNowFunc(func() time.Time { return now }),
	)

	login, err := svc.Create(ctx, session.CreateInput{
		UserID:   "user-1",
		DeviceID: "device-1",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	now = now.Add(time.Minute)
	_, err = svc.Refresh(ctx, session.RefreshInput{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}

	now = now.Add(time.Minute)
	_, err = svc.Refresh(ctx, session.RefreshInput{RefreshToken: login.RefreshToken})
	if err != session.ErrRefreshTokenReplayed {
		t.Fatalf("expected replay error, got %v", err)
	}

	state, err := svc.Get(ctx, login.Session.ID)
	if err != nil {
		t.Fatalf("get session after replay: %v", err)
	}
	if state.Status != session.StatusRevoked {
		t.Fatalf("expected revoked status after replay, got %s", state.Status)
	}
}
