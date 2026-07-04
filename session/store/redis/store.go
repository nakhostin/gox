package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nakhostin/gox/session/config"
	sessionstore "github.com/nakhostin/gox/session/store"
	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
	prefix string
}

func New(client *redis.Client, prefix string) *Store {
	if prefix == "" {
		prefix = "gox:sessions"
	}
	return &Store{client: client, prefix: prefix}
}

func (s *Store) CreateSession(ctx context.Context, input sessionstore.CreateSessionInput) (sessionstore.CreateSessionResult, error) {
	var result sessionstore.CreateSessionResult

	err := s.watch(ctx, []string{s.userSessionsKey(input.Session.UserID), s.deviceSessionsKey(input.Session.UserID, input.Session.DeviceID)}, func(tx *redis.Tx) error {
		activeUser, staleUser, err := s.fetchActiveSessions(ctx, tx, input.Session.UserID, "")
		if err != nil {
			return err
		}
		activeDevice, staleDevice, err := s.fetchActiveSessions(ctx, tx, input.Session.UserID, input.Session.DeviceID)
		if err != nil {
			return err
		}

		if input.MaxActiveSessionsPerUser > 0 && len(activeUser) >= input.MaxActiveSessionsPerUser && input.LimitBehavior == config.LimitRejectNew {
			return sessionstore.ErrActiveSessionLimit
		}
		if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" && len(activeDevice) >= input.MaxActiveSessionsPerDevice && input.LimitBehavior == config.LimitRejectNew {
			return sessionstore.ErrActiveSessionLimit
		}

		evicted := make([]sessionstore.Session, 0, 2)
		if input.MaxActiveSessionsPerUser > 0 {
			for len(activeUser) >= input.MaxActiveSessionsPerUser {
				oldest := activeUser[0]
				oldest.Status = sessionstore.StatusReplaced
				oldest.TerminationReason = "evicted"
				oldest.ReplacementSessionID = input.Session.ID
				oldest.UpdatedAt = input.Now
				oldest.RevokedAt = timePointer(input.Now)
				evicted = append(evicted, oldest)
				activeUser = activeUser[1:]
			}
		}
		if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" {
			for len(activeDevice) >= input.MaxActiveSessionsPerDevice {
				oldest := activeDevice[0]
				oldest.Status = sessionstore.StatusReplaced
				oldest.TerminationReason = "evicted"
				oldest.ReplacementSessionID = input.Session.ID
				oldest.UpdatedAt = input.Now
				oldest.RevokedAt = timePointer(input.Now)
				evicted = append(evicted, oldest)
				activeDevice = activeDevice[1:]
			}
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			s.cleanupStale(pipe, input.Session.UserID, input.Session.DeviceID, staleUser, staleDevice)
			for _, sessionRecord := range evicted {
				s.persistSession(pipe, sessionRecord)
				s.removeFromActiveIndexes(pipe, sessionRecord)
				s.revokeFamilyTokens(ctx, pipe, sessionRecord.RefreshFamilyID, input.Now)
				if input.TrackHistory {
					s.persistEvent(pipe, sessionRecord.UserID, sessionstore.SessionEvent{
						ID:         sessionRecord.ID + ":evicted",
						SessionID:  sessionRecord.ID,
						UserID:     sessionRecord.UserID,
						Type:       sessionstore.EventSessionEvicted,
						OccurredAt: input.Now,
						Reason:     "evicted_by_session_limit",
						IPAddress:  sessionRecord.IPAddress,
						UserAgent:  sessionRecord.UserAgent,
					})
				}
			}

			s.persistSession(pipe, input.Session)
			s.persistRefreshToken(pipe, input.RefreshToken, input.Session.AbsoluteExpiresAt)
			s.addToActiveIndexes(pipe, input.Session)
			if input.TrackHistory {
				s.persistEvent(pipe, input.Session.UserID, sessionstore.SessionEvent{
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
			return nil
		})
		if err != nil {
			return err
		}

		result = sessionstore.CreateSessionResult{
			Session:         input.Session,
			EvictedSessions: evicted,
		}
		return nil
	})
	if err != nil {
		return sessionstore.CreateSessionResult{}, err
	}

	return result, nil
}

func (s *Store) RefreshSession(ctx context.Context, input sessionstore.RefreshSessionInput) (sessionstore.RefreshSessionResult, error) {
	var result sessionstore.RefreshSessionResult

	refreshKey := s.refreshTokenKey(input.PresentedTokenHash)
	refreshToken, err := s.getRefreshToken(ctx, refreshKey)
	if err != nil {
		if errors.Is(err, sessionstore.ErrNotFound) {
			return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}, nil
		}
		return sessionstore.RefreshSessionResult{}, err
	}

	sessionKey := s.sessionKey(refreshToken.SessionID)
	err = s.watch(ctx, []string{refreshKey, sessionKey}, func(tx *redis.Tx) error {
		currentRefresh, err := s.getRefreshTokenFromGetter(ctx, tx, refreshKey)
		if err != nil {
			if errors.Is(err, sessionstore.ErrNotFound) {
				result = sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}
				return nil
			}
			return err
		}

		if currentRefresh.RevokedAt != nil || currentRefresh.ConsumedAt != nil {
			if input.RevokeFamilyOnRefreshReplay {
				if _, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					s.revokeFamilyTokens(ctx, pipe, currentRefresh.FamilyID, input.Now)
					s.persistEvent(pipe, currentRefresh.UserID, sessionstore.SessionEvent{
						ID:         currentRefresh.SessionID + ":replay:" + currentRefresh.TokenID,
						SessionID:  currentRefresh.SessionID,
						UserID:     currentRefresh.UserID,
						Type:       sessionstore.EventRefreshReplay,
						OccurredAt: input.Now,
						Reason:     "refresh_replay_detected",
						IPAddress:  input.IPAddress,
						UserAgent:  input.UserAgent,
					})
					return nil
				}); err != nil {
					return err
				}
			}
			result = sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionReplayed}
			return nil
		}
		if input.Now.After(currentRefresh.ExpiresAt) {
			result = sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionExpired}
			return nil
		}

		sessionRecord, err := s.getSessionFromGetter(ctx, tx, sessionKey)
		if err != nil {
			if errors.Is(err, sessionstore.ErrNotFound) {
				result = sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}
				return nil
			}
			return err
		}
		sessionRecord = normalizeSession(sessionRecord, input.Now)
		if sessionRecord.Status != sessionstore.StatusActive {
			result = sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInactive}
			return nil
		}

		if input.AccessExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
			input.AccessExpiresAt = sessionRecord.AbsoluteExpiresAt
		}
		if input.RefreshExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
			input.RefreshExpiresAt = sessionRecord.AbsoluteExpiresAt
		}
		if input.IdleExpiresAt.After(sessionRecord.AbsoluteExpiresAt) {
			input.IdleExpiresAt = sessionRecord.AbsoluteExpiresAt
		}

		currentRefresh.ConsumedAt = timePointer(input.Now)
		sessionRecord.AccessTokenVersion++
		sessionRecord.AccessExpiresAt = input.AccessExpiresAt
		sessionRecord.RefreshExpiresAt = input.RefreshExpiresAt
		sessionRecord.IdleExpiresAt = input.IdleExpiresAt
		sessionRecord.LastSeenAt = input.Now
		sessionRecord.UpdatedAt = input.Now
		sessionRecord.CurrentRefreshTokenHash = input.NewRefreshTokenHash
		sessionRecord.CurrentRefreshTokenID = input.NewRefreshTokenID
		if input.IPAddress != "" {
			sessionRecord.IPAddress = input.IPAddress
		}
		if input.UserAgent != "" {
			sessionRecord.UserAgent = input.UserAgent
		}

		nextRefresh := sessionstore.RefreshToken{
			Hash:      input.NewRefreshTokenHash,
			TokenID:   input.NewRefreshTokenID,
			SessionID: sessionRecord.ID,
			UserID:    sessionRecord.UserID,
			FamilyID:  currentRefresh.FamilyID,
			Sequence:  currentRefresh.Sequence + 1,
			CreatedAt: input.Now,
			ExpiresAt: input.RefreshExpiresAt,
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			s.persistRefreshToken(pipe, currentRefresh, sessionRecord.AbsoluteExpiresAt)
			s.persistRefreshToken(pipe, nextRefresh, sessionRecord.AbsoluteExpiresAt)
			s.persistSession(pipe, sessionRecord)
			s.addToActiveIndexes(pipe, sessionRecord)
			if input.TrackHistory {
				s.persistEvent(pipe, sessionRecord.UserID, sessionstore.SessionEvent{
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
			return nil
		})
		if err != nil {
			return err
		}

		result = sessionstore.RefreshSessionResult{
			Status:  sessionstore.RefreshSessionSuccess,
			Session: sessionRecord,
		}
		return nil
	})
	if err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}

	return result, nil
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (sessionstore.Session, error) {
	return s.getSession(ctx, s.sessionKey(sessionID))
}

func (s *Store) ListActiveSessions(ctx context.Context, userID string) ([]sessionstore.Session, error) {
	sessions, stale, err := s.fetchActiveSessions(ctx, s.client, userID, "")
	if err != nil {
		return nil, err
	}
	if len(stale) > 0 {
		pipe := s.client.Pipeline()
		s.cleanupStale(pipe, userID, "", stale, nil)
		_, _ = pipe.Exec(ctx)
	}
	return sessions, nil
}

func (s *Store) ListSessionEvents(ctx context.Context, userID string, query sessionstore.HistoryQuery) ([]sessionstore.SessionEvent, error) {
	start := int64(query.Offset)
	stop := int64(-1)
	if query.Limit > 0 {
		stop = int64(query.Offset + query.Limit - 1)
	}

	ids, err := s.client.ZRevRange(ctx, s.eventsKey(userID), start, stop).Result()
	if err != nil {
		return nil, err
	}

	events := make([]sessionstore.SessionEvent, 0, len(ids))
	for _, id := range ids {
		event, getErr := s.getEvent(ctx, userID, id)
		if getErr != nil {
			continue
		}
		if query.Since != nil && event.OccurredAt.Before(*query.Since) {
			continue
		}
		if query.Until != nil && event.OccurredAt.After(*query.Until) {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

func (s *Store) RevokeSession(ctx context.Context, input sessionstore.RevokeSessionInput) (sessionstore.Session, error) {
	return s.updateSessionStatus(ctx, input.SessionID, input.Now, input.Reason, sessionstore.StatusRevoked, sessionstore.EventSessionRevoked, input.TrackHistory)
}

func (s *Store) RevokeSessionsByUser(ctx context.Context, input sessionstore.RevokeSessionsByUserInput) ([]sessionstore.Session, error) {
	activeSessions, _, err := s.fetchActiveSessions(ctx, s.client, input.UserID, "")
	if err != nil {
		return nil, err
	}

	updated := make([]sessionstore.Session, 0, len(activeSessions))
	for _, sessionRecord := range activeSessions {
		if sessionRecord.ID == input.ExceptSessionID {
			continue
		}
		revoked, revokeErr := s.updateSessionStatus(ctx, sessionRecord.ID, input.Now, input.Reason, sessionstore.StatusRevoked, sessionstore.EventSessionRevoked, input.TrackHistory)
		if revokeErr != nil {
			return nil, revokeErr
		}
		updated = append(updated, revoked)
	}
	return updated, nil
}

func (s *Store) DisableSession(ctx context.Context, input sessionstore.DisableSessionInput) (sessionstore.Session, error) {
	return s.updateSessionStatus(ctx, input.SessionID, input.Now, input.Reason, sessionstore.StatusDisabled, sessionstore.EventSessionDisabled, input.TrackHistory)
}

func (s *Store) updateSessionStatus(ctx context.Context, sessionID string, now time.Time, reason string, status sessionstore.Status, eventType sessionstore.EventType, trackHistory bool) (sessionstore.Session, error) {
	var updated sessionstore.Session
	key := s.sessionKey(sessionID)

	err := s.watch(ctx, []string{key}, func(tx *redis.Tx) error {
		sessionRecord, err := s.getSessionFromGetter(ctx, tx, key)
		if err != nil {
			return err
		}
		sessionRecord = normalizeSession(sessionRecord, now)
		if sessionRecord.Status == sessionstore.StatusActive {
			sessionRecord.Status = status
			sessionRecord.TerminationReason = reason
			sessionRecord.UpdatedAt = now
			if status == sessionstore.StatusDisabled {
				sessionRecord.DisabledAt = timePointer(now)
			} else {
				sessionRecord.RevokedAt = timePointer(now)
			}
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			s.persistSession(pipe, sessionRecord)
			if sessionRecord.Status != sessionstore.StatusActive {
				s.removeFromActiveIndexes(pipe, sessionRecord)
				s.revokeFamilyTokens(ctx, pipe, sessionRecord.RefreshFamilyID, now)
			}
			if trackHistory {
				s.persistEvent(pipe, sessionRecord.UserID, sessionstore.SessionEvent{
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
			return nil
		})
		if err != nil {
			return err
		}

		updated = sessionRecord
		return nil
	})
	if err != nil {
		return sessionstore.Session{}, err
	}

	return updated, nil
}

func (s *Store) watch(ctx context.Context, keys []string, fn func(tx *redis.Tx) error) error {
	return s.client.Watch(ctx, fn, keys...)
}

func (s *Store) fetchActiveSessions(ctx context.Context, getter redis.Cmdable, userID string, deviceID string) ([]sessionstore.Session, []string, error) {
	var ids []string
	var err error
	if deviceID == "" {
		ids, err = getter.ZRange(ctx, s.userSessionsKey(userID), 0, -1).Result()
	} else {
		ids, err = getter.ZRange(ctx, s.deviceSessionsKey(userID, deviceID), 0, -1).Result()
	}
	if err != nil {
		return nil, nil, err
	}

	active := make([]sessionstore.Session, 0, len(ids))
	stale := make([]string, 0)
	now := time.Now().UTC()
	for _, id := range ids {
		sessionRecord, getErr := s.getSession(ctx, s.sessionKey(id))
		if getErr != nil {
			if errors.Is(getErr, sessionstore.ErrNotFound) {
				stale = append(stale, id)
				continue
			}
			return nil, nil, getErr
		}
		sessionRecord = normalizeSession(sessionRecord, now)
		if sessionRecord.Status != sessionstore.StatusActive {
			stale = append(stale, id)
			continue
		}
		active = append(active, sessionRecord)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].CreatedAt.Before(active[j].CreatedAt)
	})

	return active, stale, nil
}

func (s *Store) getSession(ctx context.Context, key string) (sessionstore.Session, error) {
	return s.getSessionFromGetter(ctx, s.client, key)
}

func (s *Store) getSessionFromGetter(ctx context.Context, getter redis.StringCmdable, key string) (sessionstore.Session, error) {
	raw, err := getter.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return sessionstore.Session{}, sessionstore.ErrNotFound
		}
		return sessionstore.Session{}, err
	}

	var sessionRecord sessionstore.Session
	if err := json.Unmarshal([]byte(raw), &sessionRecord); err != nil {
		return sessionstore.Session{}, err
	}
	return sessionRecord, nil
}

func (s *Store) getRefreshToken(ctx context.Context, key string) (sessionstore.RefreshToken, error) {
	return s.getRefreshTokenFromGetter(ctx, s.client, key)
}

func (s *Store) getRefreshTokenFromGetter(ctx context.Context, getter redis.StringCmdable, key string) (sessionstore.RefreshToken, error) {
	raw, err := getter.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return sessionstore.RefreshToken{}, sessionstore.ErrNotFound
		}
		return sessionstore.RefreshToken{}, err
	}

	var refreshToken sessionstore.RefreshToken
	if err := json.Unmarshal([]byte(raw), &refreshToken); err != nil {
		return sessionstore.RefreshToken{}, err
	}
	return refreshToken, nil
}

func (s *Store) getEvent(ctx context.Context, userID string, eventID string) (sessionstore.SessionEvent, error) {
	raw, err := s.client.Get(ctx, s.eventKey(userID, eventID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return sessionstore.SessionEvent{}, sessionstore.ErrNotFound
		}
		return sessionstore.SessionEvent{}, err
	}

	var event sessionstore.SessionEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return sessionstore.SessionEvent{}, err
	}
	return event, nil
}

func (s *Store) persistSession(pipe redis.Pipeliner, sessionRecord sessionstore.Session) {
	body, _ := json.Marshal(sessionRecord)
	pipe.Set(context.Background(), s.sessionKey(sessionRecord.ID), body, ttlUntil(sessionRecord.AbsoluteExpiresAt))
}

func (s *Store) persistRefreshToken(pipe redis.Pipeliner, refreshToken sessionstore.RefreshToken, absoluteExpiresAt time.Time) {
	body, _ := json.Marshal(refreshToken)
	ttl := ttlUntil(refreshToken.ExpiresAt)
	if familyTTL := ttlUntil(absoluteExpiresAt); familyTTL > ttl {
		ttl = familyTTL
	}
	pipe.Set(context.Background(), s.refreshTokenKey(refreshToken.Hash), body, ttl)
	pipe.SAdd(context.Background(), s.familyTokensKey(refreshToken.FamilyID), refreshToken.Hash)
	pipe.Expire(context.Background(), s.familyTokensKey(refreshToken.FamilyID), ttlUntil(absoluteExpiresAt))
}

func (s *Store) persistEvent(pipe redis.Pipeliner, userID string, event sessionstore.SessionEvent) {
	body, _ := json.Marshal(event)
	pipe.Set(context.Background(), s.eventKey(userID, event.ID), body, 180*24*time.Hour)
	pipe.ZAdd(context.Background(), s.eventsKey(userID), redis.Z{
		Score:  float64(event.OccurredAt.UnixNano()),
		Member: event.ID,
	})
}

func (s *Store) addToActiveIndexes(pipe redis.Pipeliner, sessionRecord sessionstore.Session) {
	pipe.ZAdd(context.Background(), s.userSessionsKey(sessionRecord.UserID), redis.Z{
		Score:  float64(sessionRecord.CreatedAt.UnixNano()),
		Member: sessionRecord.ID,
	})
	if sessionRecord.DeviceID != "" {
		pipe.ZAdd(context.Background(), s.deviceSessionsKey(sessionRecord.UserID, sessionRecord.DeviceID), redis.Z{
			Score:  float64(sessionRecord.CreatedAt.UnixNano()),
			Member: sessionRecord.ID,
		})
	}
}

func (s *Store) removeFromActiveIndexes(pipe redis.Pipeliner, sessionRecord sessionstore.Session) {
	pipe.ZRem(context.Background(), s.userSessionsKey(sessionRecord.UserID), sessionRecord.ID)
	if sessionRecord.DeviceID != "" {
		pipe.ZRem(context.Background(), s.deviceSessionsKey(sessionRecord.UserID, sessionRecord.DeviceID), sessionRecord.ID)
	}
}

func (s *Store) revokeFamilyTokens(ctx context.Context, pipe redis.Pipeliner, familyID string, now time.Time) {
	hashes, err := s.client.SMembers(ctx, s.familyTokensKey(familyID)).Result()
	if err != nil {
		return
	}
	for _, hash := range hashes {
		refreshToken, getErr := s.getRefreshToken(ctx, s.refreshTokenKey(hash))
		if getErr != nil {
			continue
		}
		refreshToken.RevokedAt = timePointer(now)
		body, _ := json.Marshal(refreshToken)
		pipe.Set(context.Background(), s.refreshTokenKey(hash), body, ttlUntil(refreshToken.ExpiresAt))
	}
}

func (s *Store) cleanupStale(pipe redis.Pipeliner, userID string, deviceID string, staleUser []string, staleDevice []string) {
	if len(staleUser) > 0 {
		members := make([]any, 0, len(staleUser))
		for _, item := range staleUser {
			members = append(members, item)
		}
		pipe.ZRem(context.Background(), s.userSessionsKey(userID), members...)
	}
	if deviceID != "" && len(staleDevice) > 0 {
		members := make([]any, 0, len(staleDevice))
		for _, item := range staleDevice {
			members = append(members, item)
		}
		pipe.ZRem(context.Background(), s.deviceSessionsKey(userID, deviceID), members...)
	}
}

func (s *Store) sessionKey(sessionID string) string {
	return fmt.Sprintf("%s:session:%s", s.prefix, sessionID)
}

func (s *Store) refreshTokenKey(hash string) string {
	return fmt.Sprintf("%s:refresh:%s", s.prefix, hash)
}

func (s *Store) userSessionsKey(userID string) string {
	return fmt.Sprintf("%s:user:%s:sessions", s.prefix, userID)
}

func (s *Store) deviceSessionsKey(userID string, deviceID string) string {
	safeDeviceID := strings.ReplaceAll(deviceID, ":", "_")
	return fmt.Sprintf("%s:user:%s:device:%s:sessions", s.prefix, userID, safeDeviceID)
}

func (s *Store) familyTokensKey(familyID string) string {
	return fmt.Sprintf("%s:family:%s:tokens", s.prefix, familyID)
}

func (s *Store) eventsKey(userID string) string {
	return fmt.Sprintf("%s:user:%s:events", s.prefix, userID)
}

func (s *Store) eventKey(userID string, eventID string) string {
	return fmt.Sprintf("%s:event:%s:%s", s.prefix, userID, eventID)
}

func ttlUntil(target time.Time) time.Duration {
	ttl := time.Until(target.UTC())
	if ttl <= 0 {
		return time.Second
	}
	return ttl
}

func normalizeSession(sessionRecord sessionstore.Session, now time.Time) sessionstore.Session {
	if sessionRecord.Status != sessionstore.StatusActive {
		return sessionRecord
	}
	if now.After(sessionRecord.AbsoluteExpiresAt) || now.After(sessionRecord.RefreshExpiresAt) || now.After(sessionRecord.IdleExpiresAt) {
		sessionRecord.Status = sessionstore.StatusExpired
	}
	return sessionRecord
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
