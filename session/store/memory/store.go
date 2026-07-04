package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	sessionconfig "github.com/nakhostin/gox/session/config"
	sessionstore "github.com/nakhostin/gox/session/store"
)

type Store struct {
	mu            sync.Mutex
	sessions      map[string]sessionstore.Session
	refreshTokens map[string]sessionstore.RefreshToken
	events        map[string][]sessionstore.SessionEvent
}

func New() *Store {
	return &Store{
		sessions:      map[string]sessionstore.Session{},
		refreshTokens: map[string]sessionstore.RefreshToken{},
		events:        map[string][]sessionstore.SessionEvent{},
	}
}

func (s *Store) CreateSession(_ context.Context, input sessionstore.CreateSessionInput) (sessionstore.CreateSessionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(input.Now, input.TrackHistory)

	activeUserSessions := s.activeSessionsForUserLocked(input.Session.UserID)
	if input.MaxActiveSessionsPerUser > 0 && len(activeUserSessions) >= input.MaxActiveSessionsPerUser {
		if input.LimitBehavior == sessionconfig.LimitRejectNew {
			if input.TrackHistory {
				s.appendEventLocked(input.Session.UserID, sessionstore.SessionEvent{
					ID:         input.Session.ID + ":limit:user",
					SessionID:  input.Session.ID,
					UserID:     input.Session.UserID,
					Type:       sessionstore.EventLoginRejectedByLimit,
					OccurredAt: input.Now,
					Reason:     "max_active_sessions_per_user",
					IPAddress:  input.Session.IPAddress,
					UserAgent:  input.Session.UserAgent,
				})
			}
			return sessionstore.CreateSessionResult{}, sessionstore.ErrActiveSessionLimit
		}
	}

	activeDeviceSessions := s.activeSessionsForDeviceLocked(input.Session.UserID, input.Session.DeviceID)
	if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" && len(activeDeviceSessions) >= input.MaxActiveSessionsPerDevice {
		if input.LimitBehavior == sessionconfig.LimitRejectNew {
			if input.TrackHistory {
				s.appendEventLocked(input.Session.UserID, sessionstore.SessionEvent{
					ID:         input.Session.ID + ":limit:device",
					SessionID:  input.Session.ID,
					UserID:     input.Session.UserID,
					Type:       sessionstore.EventLoginRejectedByLimit,
					OccurredAt: input.Now,
					Reason:     "max_active_sessions_per_device",
					IPAddress:  input.Session.IPAddress,
					UserAgent:  input.Session.UserAgent,
				})
			}
			return sessionstore.CreateSessionResult{}, sessionstore.ErrActiveSessionLimit
		}
	}

	evicted := make([]sessionstore.Session, 0, 2)
	if input.MaxActiveSessionsPerUser > 0 {
		for len(activeUserSessions) >= input.MaxActiveSessionsPerUser {
			oldest := activeUserSessions[0]
			s.evictSessionLocked(oldest.ID, input.Session.ID, input.Now, input.TrackHistory)
			evicted = append(evicted, s.sessions[oldest.ID])
			activeUserSessions = s.activeSessionsForUserLocked(input.Session.UserID)
		}
	}
	if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" {
		for len(activeDeviceSessions) >= input.MaxActiveSessionsPerDevice {
			oldest := activeDeviceSessions[0]
			s.evictSessionLocked(oldest.ID, input.Session.ID, input.Now, input.TrackHistory)
			evicted = append(evicted, s.sessions[oldest.ID])
			activeDeviceSessions = s.activeSessionsForDeviceLocked(input.Session.UserID, input.Session.DeviceID)
		}
	}

	s.sessions[input.Session.ID] = cloneSession(input.Session)
	s.refreshTokens[input.RefreshToken.Hash] = input.RefreshToken
	if input.TrackHistory {
		s.appendEventLocked(input.Session.UserID, sessionstore.SessionEvent{
			ID:         input.Session.ID + ":created",
			SessionID:  input.Session.ID,
			UserID:     input.Session.UserID,
			Type:       sessionstore.EventSessionCreated,
			OccurredAt: input.Now,
			Reason:     "created",
			IPAddress:  input.Session.IPAddress,
			UserAgent:  input.Session.UserAgent,
			Metadata:   cloneMap(input.Session.Metadata),
		})
	}

	return sessionstore.CreateSessionResult{
		Session:         cloneSession(input.Session),
		EvictedSessions: cloneSessions(evicted),
	}, nil
}

func (s *Store) RefreshSession(_ context.Context, input sessionstore.RefreshSessionInput) (sessionstore.RefreshSessionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(input.Now, input.TrackHistory)

	refreshToken, ok := s.refreshTokens[input.PresentedTokenHash]
	if !ok {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}, nil
	}
	if refreshToken.RevokedAt != nil || refreshToken.ConsumedAt != nil {
		if input.RevokeFamilyOnRefreshReplay {
			s.revokeFamilyLocked(refreshToken.FamilyID, input.Now, "refresh_replay", input.TrackHistory)
		}
		s.appendEventLocked(refreshToken.UserID, sessionstore.SessionEvent{
			ID:         refreshToken.SessionID + ":replay:" + refreshToken.TokenID,
			SessionID:  refreshToken.SessionID,
			UserID:     refreshToken.UserID,
			Type:       sessionstore.EventRefreshReplay,
			OccurredAt: input.Now,
			Reason:     "refresh_replay_detected",
			IPAddress:  input.IPAddress,
			UserAgent:  input.UserAgent,
		})
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionReplayed}, nil
	}
	if input.Now.After(refreshToken.ExpiresAt) {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionExpired}, nil
	}

	sessionRecord, ok := s.sessions[refreshToken.SessionID]
	if !ok {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}, nil
	}
	if sessionRecord.Status != sessionstore.StatusActive {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInactive}, nil
	}

	refreshToken.ConsumedAt = timePointer(input.Now)
	s.refreshTokens[input.PresentedTokenHash] = refreshToken

	if input.RefreshExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
		input.RefreshExpiresAt = sessionRecord.AbsoluteExpiresAt
	}
	if input.AccessExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
		input.AccessExpiresAt = sessionRecord.AbsoluteExpiresAt
	}
	if input.IdleExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
		input.IdleExpiresAt = sessionRecord.AbsoluteExpiresAt
	}

	sessionRecord.AccessTokenVersion++
	sessionRecord.AccessExpiresAt = input.AccessExpiresAt
	sessionRecord.RefreshExpiresAt = input.RefreshExpiresAt
	sessionRecord.IdleExpiresAt = input.IdleExpiresAt
	sessionRecord.LastSeenAt = input.Now
	sessionRecord.UpdatedAt = input.Now
	if input.IPAddress != "" {
		sessionRecord.IPAddress = input.IPAddress
	}
	if input.UserAgent != "" {
		sessionRecord.UserAgent = input.UserAgent
	}
	sessionRecord.CurrentRefreshTokenHash = input.NewRefreshTokenHash
	sessionRecord.CurrentRefreshTokenID = input.NewRefreshTokenID
	s.sessions[sessionRecord.ID] = cloneSession(sessionRecord)

	s.refreshTokens[input.NewRefreshTokenHash] = sessionstore.RefreshToken{
		Hash:      input.NewRefreshTokenHash,
		TokenID:   input.NewRefreshTokenID,
		SessionID: sessionRecord.ID,
		UserID:    sessionRecord.UserID,
		FamilyID:  refreshToken.FamilyID,
		Sequence:  refreshToken.Sequence + 1,
		CreatedAt: input.Now,
		ExpiresAt: input.RefreshExpiresAt,
	}
	if input.TrackHistory {
		s.appendEventLocked(sessionRecord.UserID, sessionstore.SessionEvent{
			ID:         sessionRecord.ID + ":refresh:" + input.NewRefreshTokenID,
			SessionID:  sessionRecord.ID,
			UserID:     sessionRecord.UserID,
			Type:       sessionstore.EventSessionRefreshed,
			OccurredAt: input.Now,
			Reason:     "rotated_refresh_token",
			IPAddress:  sessionRecord.IPAddress,
			UserAgent:  sessionRecord.UserAgent,
		})
	}

	return sessionstore.RefreshSessionResult{
		Status:  sessionstore.RefreshSessionSuccess,
		Session: cloneSession(sessionRecord),
	}, nil
}

func (s *Store) GetSession(_ context.Context, sessionID string) (sessionstore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(time.Now().UTC(), false)
	sessionRecord, ok := s.sessions[sessionID]
	if !ok {
		return sessionstore.Session{}, sessionstore.ErrNotFound
	}
	return cloneSession(sessionRecord), nil
}

func (s *Store) ListActiveSessions(_ context.Context, userID string) ([]sessionstore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(time.Now().UTC(), false)
	return cloneSessions(s.activeSessionsForUserLocked(userID)), nil
}

func (s *Store) ListSessionEvents(_ context.Context, userID string, query sessionstore.HistoryQuery) ([]sessionstore.SessionEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	events := s.events[userID]
	filtered := make([]sessionstore.SessionEvent, 0, len(events))
	for _, event := range events {
		if query.Since != nil && event.OccurredAt.Before(*query.Since) {
			continue
		}
		if query.Until != nil && event.OccurredAt.After(*query.Until) {
			continue
		}
		filtered = append(filtered, cloneEvent(event))
	}

	if query.Offset > 0 {
		if query.Offset >= len(filtered) {
			return []sessionstore.SessionEvent{}, nil
		}
		filtered = filtered[query.Offset:]
	}
	if query.Limit > 0 && len(filtered) > query.Limit {
		filtered = filtered[:query.Limit]
	}

	return filtered, nil
}

func (s *Store) RevokeSession(_ context.Context, input sessionstore.RevokeSessionInput) (sessionstore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(input.Now, input.TrackHistory)
	sessionRecord, ok := s.sessions[input.SessionID]
	if !ok {
		return sessionstore.Session{}, sessionstore.ErrNotFound
	}
	if sessionRecord.Status == sessionstore.StatusActive {
		s.revokeSessionLocked(&sessionRecord, input.Now, input.Reason, sessionstore.EventSessionRevoked, input.TrackHistory)
		s.sessions[sessionRecord.ID] = sessionRecord
	}
	return cloneSession(sessionRecord), nil
}

func (s *Store) RevokeSessionsByUser(_ context.Context, input sessionstore.RevokeSessionsByUserInput) ([]sessionstore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(input.Now, input.TrackHistory)
	revoked := make([]sessionstore.Session, 0)
	for id, sessionRecord := range s.sessions {
		if sessionRecord.UserID != input.UserID || sessionRecord.ID == input.ExceptSessionID {
			continue
		}
		if sessionRecord.Status != sessionstore.StatusActive {
			continue
		}

		s.revokeSessionLocked(&sessionRecord, input.Now, input.Reason, sessionstore.EventSessionRevoked, input.TrackHistory)
		s.sessions[id] = sessionRecord
		revoked = append(revoked, cloneSession(sessionRecord))
	}

	return revoked, nil
}

func (s *Store) DisableSession(_ context.Context, input sessionstore.DisableSessionInput) (sessionstore.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessionsLocked(input.Now, input.TrackHistory)
	sessionRecord, ok := s.sessions[input.SessionID]
	if !ok {
		return sessionstore.Session{}, sessionstore.ErrNotFound
	}
	if sessionRecord.Status == sessionstore.StatusActive {
		sessionRecord.Status = sessionstore.StatusDisabled
		sessionRecord.DisabledAt = timePointer(input.Now)
		sessionRecord.TerminationReason = input.Reason
		sessionRecord.UpdatedAt = input.Now
		s.revokeRefreshTokensForSessionLocked(sessionRecord.ID, input.Now)
		s.sessions[input.SessionID] = sessionRecord
		if input.TrackHistory {
			s.appendEventLocked(sessionRecord.UserID, sessionstore.SessionEvent{
				ID:         sessionRecord.ID + ":disabled",
				SessionID:  sessionRecord.ID,
				UserID:     sessionRecord.UserID,
				Type:       sessionstore.EventSessionDisabled,
				OccurredAt: input.Now,
				Reason:     input.Reason,
				IPAddress:  sessionRecord.IPAddress,
				UserAgent:  sessionRecord.UserAgent,
			})
		}
	}
	return cloneSession(sessionRecord), nil
}

func (s *Store) expireSessionsLocked(now time.Time, trackHistory bool) {
	for id, sessionRecord := range s.sessions {
		if sessionRecord.Status != sessionstore.StatusActive {
			continue
		}
		if now.After(sessionRecord.AbsoluteExpiresAt) || now.After(sessionRecord.RefreshExpiresAt) || now.After(sessionRecord.IdleExpiresAt) {
			sessionRecord.Status = sessionstore.StatusExpired
			sessionRecord.TerminationReason = "expired"
			sessionRecord.UpdatedAt = now
			s.revokeRefreshTokensForSessionLocked(sessionRecord.ID, now)
			s.sessions[id] = sessionRecord
			if trackHistory {
				s.appendEventLocked(sessionRecord.UserID, sessionstore.SessionEvent{
					ID:         sessionRecord.ID + ":expired",
					SessionID:  sessionRecord.ID,
					UserID:     sessionRecord.UserID,
					Type:       sessionstore.EventSessionExpired,
					OccurredAt: now,
					Reason:     "expired",
					IPAddress:  sessionRecord.IPAddress,
					UserAgent:  sessionRecord.UserAgent,
				})
			}
		}
	}
}

func (s *Store) activeSessionsForUserLocked(userID string) []sessionstore.Session {
	sessions := make([]sessionstore.Session, 0)
	for _, sessionRecord := range s.sessions {
		if sessionRecord.UserID == userID && sessionRecord.Status == sessionstore.StatusActive {
			sessions = append(sessions, cloneSession(sessionRecord))
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.Before(sessions[j].CreatedAt)
	})
	return sessions
}

func (s *Store) activeSessionsForDeviceLocked(userID string, deviceID string) []sessionstore.Session {
	sessions := make([]sessionstore.Session, 0)
	for _, sessionRecord := range s.sessions {
		if sessionRecord.UserID == userID && sessionRecord.DeviceID == deviceID && sessionRecord.Status == sessionstore.StatusActive {
			sessions = append(sessions, cloneSession(sessionRecord))
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.Before(sessions[j].CreatedAt)
	})
	return sessions
}

func (s *Store) evictSessionLocked(sessionID string, replacementSessionID string, now time.Time, trackHistory bool) {
	sessionRecord, ok := s.sessions[sessionID]
	if !ok || sessionRecord.Status != sessionstore.StatusActive {
		return
	}

	sessionRecord.Status = sessionstore.StatusReplaced
	sessionRecord.RevokedAt = timePointer(now)
	sessionRecord.TerminationReason = "evicted"
	sessionRecord.ReplacementSessionID = replacementSessionID
	sessionRecord.UpdatedAt = now
	s.revokeRefreshTokensForSessionLocked(sessionRecord.ID, now)
	s.sessions[sessionID] = sessionRecord

	if trackHistory {
		s.appendEventLocked(sessionRecord.UserID, sessionstore.SessionEvent{
			ID:         sessionRecord.ID + ":evicted",
			SessionID:  sessionRecord.ID,
			UserID:     sessionRecord.UserID,
			Type:       sessionstore.EventSessionEvicted,
			OccurredAt: now,
			Reason:     "evicted_by_session_limit",
			IPAddress:  sessionRecord.IPAddress,
			UserAgent:  sessionRecord.UserAgent,
		})
	}
}

func (s *Store) revokeFamilyLocked(familyID string, now time.Time, reason string, trackHistory bool) {
	for hash, refreshToken := range s.refreshTokens {
		if refreshToken.FamilyID != familyID {
			continue
		}
		if refreshToken.RevokedAt == nil {
			refreshToken.RevokedAt = timePointer(now)
			s.refreshTokens[hash] = refreshToken
		}

		sessionRecord, ok := s.sessions[refreshToken.SessionID]
		if !ok || sessionRecord.Status != sessionstore.StatusActive {
			continue
		}
		s.revokeSessionLocked(&sessionRecord, now, reason, sessionstore.EventSessionRevoked, trackHistory)
		s.sessions[sessionRecord.ID] = sessionRecord
	}
}

func (s *Store) revokeSessionLocked(sessionRecord *sessionstore.Session, now time.Time, reason string, eventType sessionstore.EventType, trackHistory bool) {
	sessionRecord.Status = sessionstore.StatusRevoked
	sessionRecord.RevokedAt = timePointer(now)
	sessionRecord.TerminationReason = reason
	sessionRecord.UpdatedAt = now
	s.revokeRefreshTokensForSessionLocked(sessionRecord.ID, now)
	if trackHistory {
		s.appendEventLocked(sessionRecord.UserID, sessionstore.SessionEvent{
			ID:         sessionRecord.ID + ":" + string(eventType) + ":" + now.Format(time.RFC3339Nano),
			SessionID:  sessionRecord.ID,
			UserID:     sessionRecord.UserID,
			Type:       eventType,
			OccurredAt: now,
			Reason:     reason,
			IPAddress:  sessionRecord.IPAddress,
			UserAgent:  sessionRecord.UserAgent,
		})
	}
}

func (s *Store) revokeRefreshTokensForSessionLocked(sessionID string, now time.Time) {
	for hash, refreshToken := range s.refreshTokens {
		if refreshToken.SessionID != sessionID {
			continue
		}
		refreshToken.RevokedAt = timePointer(now)
		s.refreshTokens[hash] = refreshToken
	}
}

func (s *Store) appendEventLocked(userID string, event sessionstore.SessionEvent) {
	s.events[userID] = append(s.events[userID], cloneEvent(event))
}

func cloneSession(in sessionstore.Session) sessionstore.Session {
	in.Claims = cloneMap(in.Claims)
	in.Metadata = cloneMap(in.Metadata)
	return in
}

func cloneSessions(in []sessionstore.Session) []sessionstore.Session {
	out := make([]sessionstore.Session, 0, len(in))
	for _, item := range in {
		out = append(out, cloneSession(item))
	}
	return out
}

func cloneEvent(in sessionstore.SessionEvent) sessionstore.SessionEvent {
	in.Metadata = cloneMap(in.Metadata)
	return in
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

func timePointer(t time.Time) *time.Time {
	value := t
	return &value
}
