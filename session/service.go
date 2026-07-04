package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	sessionconfig "github.com/nakhostin/gox/session/config"
	sessionstore "github.com/nakhostin/gox/session/store"
	sessiontoken "github.com/nakhostin/gox/session/token"
)

type RefreshProvider interface {
	Generate(ctx context.Context, length int) (string, error)
}

type OpaqueRefreshProvider struct {
	Generator func(int) (string, error)
}

func (p OpaqueRefreshProvider) Generate(_ context.Context, length int) (string, error) {
	if p.Generator != nil {
		return p.Generator(length)
	}
	return randomToken(length)
}

type Service struct {
	cfg                   sessionconfig.Config
	store                 sessionstore.Store
	accessProvider        sessiontoken.Provider
	refreshProvider       RefreshProvider
	now                   func() time.Time
	idGenerator           func() string
	refreshTokenGenerator func(int) (string, error)
}

func New(
	cfg sessionconfig.Config,
	sessionStore sessionstore.Store,
	accessProvider sessiontoken.Provider,
	refreshProvider RefreshProvider,
	opts ...Option,
) *Service {
	svc := &Service{
		cfg:                   cfg,
		store:                 sessionStore,
		accessProvider:        accessProvider,
		refreshProvider:       refreshProvider,
		now:                   time.Now,
		idGenerator:           newID,
		refreshTokenGenerator: randomToken,
	}

	for _, opt := range opts {
		opt(svc)
	}

	if svc.refreshProvider == nil {
		svc.refreshProvider = OpaqueRefreshProvider{
			Generator: svc.refreshTokenGenerator,
		}
	}

	return svc
}

func (s *Service) Create(ctx context.Context, in CreateInput) (CreateResult, error) {
	if err := s.validateDependencies(); err != nil {
		return CreateResult{}, err
	}
	if in.UserID == "" {
		return CreateResult{}, ErrSessionInvalid
	}

	now := s.now().UTC()
	sessionID := s.idGenerator()
	refreshTokenID := s.idGenerator()
	familyID := s.idGenerator()
	refreshRaw, err := s.refreshProvider.Generate(ctx, s.cfg.GetRefreshTokenLength())
	if err != nil {
		return CreateResult{}, fmt.Errorf("%w: %v", ErrInternal, err)
	}

	accessExpiresAt := now.Add(s.cfg.GetAccessTokenTTL())
	refreshExpiresAt := now.Add(s.cfg.GetRefreshTokenTTL())
	idleExpiresAt := now.Add(s.cfg.GetIdleTimeout())
	absoluteExpiresAt := now.Add(s.cfg.GetAbsoluteTTL())
	if refreshExpiresAt.After(absoluteExpiresAt) {
		refreshExpiresAt = absoluteExpiresAt
	}
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}

	sessionRecord := sessionstore.Session{
		ID:                      sessionID,
		UserID:                  in.UserID,
		Status:                  sessionstore.StatusActive,
		CreatedAt:               now,
		UpdatedAt:               now,
		LastSeenAt:              now,
		AccessExpiresAt:         accessExpiresAt,
		RefreshExpiresAt:        refreshExpiresAt,
		IdleExpiresAt:           idleExpiresAt,
		AbsoluteExpiresAt:       absoluteExpiresAt,
		DeviceID:                in.DeviceID,
		DeviceName:              in.DeviceName,
		Platform:                in.Platform,
		IPAddress:               in.IPAddress,
		UserAgent:               in.UserAgent,
		AccessTokenVersion:      1,
		RefreshFamilyID:         familyID,
		CurrentRefreshTokenID:   refreshTokenID,
		CurrentRefreshTokenHash: s.hashRefreshToken(refreshRaw),
		Claims:                  cloneMap(in.Claims),
		Metadata:                cloneMap(in.Metadata),
	}

	storeResult, err := s.store.CreateSession(ctx, sessionstore.CreateSessionInput{
		Now:     now,
		Session: sessionRecord,
		RefreshToken: sessionstore.RefreshToken{
			Hash:      sessionRecord.CurrentRefreshTokenHash,
			TokenID:   refreshTokenID,
			SessionID: sessionID,
			UserID:    in.UserID,
			FamilyID:  familyID,
			Sequence:  1,
			CreatedAt: now,
			ExpiresAt: refreshExpiresAt,
		},
		MaxActiveSessionsPerUser:   s.cfg.GetMaxActiveSessionsPerUser(),
		MaxActiveSessionsPerDevice: s.cfg.GetMaxActiveSessionsPerDevice(),
		LimitBehavior:              s.cfg.GetLimitBehavior(),
		TrackHistory:               s.cfg.GetTrackHistory(),
	})
	if err != nil {
		if errors.Is(err, ErrMaxSessionsReached) {
			return CreateResult{}, err
		}
		return CreateResult{}, mapStoreError(err)
	}

	accessToken, err := s.issueAccessToken(ctx, storeResult.Session)
	if err != nil {
		return CreateResult{}, err
	}

	return CreateResult{
		Session:      storeResult.Session,
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, in RefreshInput) (RefreshResult, error) {
	if err := s.validateDependencies(); err != nil {
		return RefreshResult{}, err
	}
	if in.RefreshToken == "" {
		return RefreshResult{}, ErrRefreshTokenInvalid
	}

	now := s.now().UTC()
	refreshRaw, err := s.refreshProvider.Generate(ctx, s.cfg.GetRefreshTokenLength())
	if err != nil {
		return RefreshResult{}, fmt.Errorf("%w: %v", ErrInternal, err)
	}

	refreshExpiresAt := now.Add(s.cfg.GetRefreshTokenTTL())
	idleExpiresAt := now.Add(s.cfg.GetIdleTimeout())
	newRefreshHash := s.hashRefreshToken(refreshRaw)

	storeResult, err := s.store.RefreshSession(ctx, sessionstore.RefreshSessionInput{
		Now:                         now,
		PresentedTokenHash:          s.hashRefreshToken(in.RefreshToken),
		NewRefreshTokenHash:         newRefreshHash,
		NewRefreshTokenID:           s.idGenerator(),
		AccessExpiresAt:             now.Add(s.cfg.GetAccessTokenTTL()),
		RefreshExpiresAt:            refreshExpiresAt,
		IdleExpiresAt:               idleExpiresAt,
		IPAddress:                   in.IPAddress,
		UserAgent:                   in.UserAgent,
		TrackHistory:                s.cfg.GetTrackHistory(),
		RevokeFamilyOnRefreshReplay: s.cfg.GetRevokeFamilyOnRefreshReplay(),
	})
	if err != nil {
		return RefreshResult{}, mapStoreError(err)
	}

	switch storeResult.Status {
	case sessionstore.RefreshSessionSuccess:
		accessToken, issueErr := s.issueAccessToken(ctx, storeResult.Session)
		if issueErr != nil {
			return RefreshResult{}, issueErr
		}

		return RefreshResult{
			Session:      storeResult.Session,
			AccessToken:  accessToken,
			RefreshToken: refreshRaw,
		}, nil
	case sessionstore.RefreshSessionExpired:
		return RefreshResult{}, ErrRefreshTokenExpired
	case sessionstore.RefreshSessionReplayed:
		return RefreshResult{}, ErrRefreshTokenReplayed
	case sessionstore.RefreshSessionInactive:
		return RefreshResult{}, ErrSessionInvalid
	default:
		return RefreshResult{}, ErrRefreshTokenInvalid
	}
}

func (s *Service) ValidateAccessToken(ctx context.Context, raw string) (Claims, error) {
	if err := s.validateDependencies(); err != nil {
		return Claims{}, err
	}

	claims, err := s.accessProvider.Validate(ctx, raw)
	if err != nil {
		switch {
		case errors.Is(err, sessiontoken.ErrExpiredToken):
			return Claims{}, ErrAccessTokenExpired
		case errors.Is(err, sessiontoken.ErrInvalidToken):
			return Claims{}, ErrAccessTokenInvalid
		default:
			return Claims{}, fmt.Errorf("%w: %v", ErrInternal, err)
		}
	}

	sessionRecord, err := s.store.GetSession(ctx, claims.SessionID)
	if err != nil {
		return Claims{}, mapStoreError(err)
	}

	if err := s.ensureSessionUsable(sessionRecord, s.now().UTC()); err != nil {
		return Claims{}, err
	}

	if claims.ExpiresAt.Before(s.now().UTC()) {
		return Claims{}, ErrAccessTokenExpired
	}

	return claims, nil
}

func (s *Service) Get(ctx context.Context, sessionID string) (Session, error) {
	record, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return Session{}, mapStoreError(err)
	}

	return s.normalizeSession(record, s.now().UTC()), nil
}

func (s *Service) ListActive(ctx context.Context, userID string) ([]Session, error) {
	records, err := s.store.ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, mapStoreError(err)
	}

	now := s.now().UTC()
	sessions := make([]Session, 0, len(records))
	for _, record := range records {
		record = s.normalizeSession(record, now)
		if record.Status == sessionstore.StatusActive {
			sessions = append(sessions, record)
		}
	}

	return sessions, nil
}

func (s *Service) ListHistory(ctx context.Context, userID string, query HistoryQuery) ([]SessionEvent, error) {
	events, err := s.store.ListSessionEvents(ctx, userID, sessionstore.HistoryQuery(query))
	if err != nil {
		return nil, mapStoreError(err)
	}

	return events, nil
}

func (s *Service) Revoke(ctx context.Context, sessionID string, reason string) error {
	_, err := s.store.RevokeSession(ctx, sessionstore.RevokeSessionInput{
		Now:          s.now().UTC(),
		SessionID:    sessionID,
		Reason:       reason,
		TrackHistory: s.cfg.GetTrackHistory(),
	})
	return mapStoreError(err)
}

func (s *Service) RevokeAll(ctx context.Context, userID string) error {
	_, err := s.store.RevokeSessionsByUser(ctx, sessionstore.RevokeSessionsByUserInput{
		Now:          s.now().UTC(),
		UserID:       userID,
		Reason:       "revoke_all",
		TrackHistory: s.cfg.GetTrackHistory(),
	})
	return mapStoreError(err)
}

func (s *Service) RevokeOthers(ctx context.Context, userID string, currentSessionID string) error {
	_, err := s.store.RevokeSessionsByUser(ctx, sessionstore.RevokeSessionsByUserInput{
		Now:             s.now().UTC(),
		UserID:          userID,
		ExceptSessionID: currentSessionID,
		Reason:          "revoke_others",
		TrackHistory:    s.cfg.GetTrackHistory(),
	})
	return mapStoreError(err)
}

func (s *Service) Disable(ctx context.Context, sessionID string, reason string) error {
	_, err := s.store.DisableSession(ctx, sessionstore.DisableSessionInput{
		Now:          s.now().UTC(),
		SessionID:    sessionID,
		Reason:       reason,
		TrackHistory: s.cfg.GetTrackHistory(),
	})
	return mapStoreError(err)
}

func (s *Service) issueAccessToken(ctx context.Context, sessionRecord sessionstore.Session) (string, error) {
	tokenID := fmt.Sprintf("%s:%d", sessionRecord.ID, sessionRecord.AccessTokenVersion)
	raw, err := s.accessProvider.Issue(ctx, sessiontoken.IssueInput{
		Subject:   sessionRecord.UserID,
		SessionID: sessionRecord.ID,
		TokenID:   tokenID,
		IssuedAt:  s.now().UTC(),
		ExpiresAt: sessionRecord.AccessExpiresAt,
		Values:    cloneMap(sessionRecord.Claims),
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInternal, err)
	}

	return raw, nil
}

func (s *Service) hashRefreshToken(raw string) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.GetRefreshTokenSecret()))
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) validateDependencies() error {
	switch {
	case s.store == nil:
		return ErrInvalidConfiguration
	case s.accessProvider == nil:
		return ErrInvalidConfiguration
	case s.refreshProvider == nil:
		return ErrInvalidConfiguration
	case s.cfg.GetRefreshTokenLength() <= 0:
		return ErrInvalidConfiguration
	case s.cfg.GetAccessTokenTTL() <= 0:
		return ErrInvalidConfiguration
	case s.cfg.GetRefreshTokenTTL() <= 0:
		return ErrInvalidConfiguration
	case s.cfg.GetIdleTimeout() <= 0:
		return ErrInvalidConfiguration
	case s.cfg.GetAbsoluteTTL() <= 0:
		return ErrInvalidConfiguration
	default:
		return nil
	}
}

func (s *Service) ensureSessionUsable(record sessionstore.Session, now time.Time) error {
	record = s.normalizeSession(record, now)
	switch record.Status {
	case sessionstore.StatusActive:
		return nil
	case sessionstore.StatusDisabled:
		return ErrSessionDisabled
	case sessionstore.StatusRevoked, sessionstore.StatusReplaced:
		return ErrSessionRevoked
	case sessionstore.StatusExpired:
		return ErrSessionExpired
	default:
		return ErrSessionInvalid
	}
}

func (s *Service) normalizeSession(record sessionstore.Session, now time.Time) sessionstore.Session {
	if record.Status != sessionstore.StatusActive {
		return record
	}

	if now.After(record.AbsoluteExpiresAt) || now.After(record.RefreshExpiresAt) || now.After(record.IdleExpiresAt) {
		record.Status = sessionstore.StatusExpired
	}

	return record
}

func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sessionstore.ErrNotFound):
		return ErrSessionNotFound
	case errors.Is(err, sessionstore.ErrActiveSessionLimit):
		return ErrMaxSessionsReached
	default:
		return err
	}
}

func newID() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(buf)
}

func randomToken(length int) (string, error) {
	if length <= 0 {
		return "", ErrInvalidConfiguration
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func cloneMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}

	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}

	return dst
}
