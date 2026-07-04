package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sessionconfig "github.com/nakhostin/gox/session/config"
	sessionstore "github.com/nakhostin/gox/session/store"
)

type Store struct {
	db     *sql.DB
	schema string
}

func New(db *sql.DB, schema string) *Store {
	if schema == "" {
		schema = "public"
	}
	return &Store{db: db, schema: schema}
}

func (s *Store) CreateSchema(ctx context.Context) error {
	ddl := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			last_seen_at TIMESTAMPTZ NOT NULL,
			access_expires_at TIMESTAMPTZ NOT NULL,
			refresh_expires_at TIMESTAMPTZ NOT NULL,
			idle_expires_at TIMESTAMPTZ NOT NULL,
			absolute_expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ NULL,
			disabled_at TIMESTAMPTZ NULL,
			termination_reason TEXT NOT NULL DEFAULT '',
			replacement_session_id TEXT NOT NULL DEFAULT '',
			device_id TEXT NOT NULL DEFAULT '',
			device_name TEXT NOT NULL DEFAULT '',
			platform TEXT NOT NULL DEFAULT '',
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			access_token_version BIGINT NOT NULL,
			refresh_family_id TEXT NOT NULL,
			current_refresh_token_id TEXT NOT NULL,
			current_refresh_token_hash TEXT NOT NULL,
			claims JSONB NOT NULL DEFAULT '{}'::jsonb,
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb
		)`, s.qualify("")),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_sessions_user_status_created_at ON %s.sessions(user_id, status, created_at)`, s.schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_sessions_family ON %s.sessions(refresh_family_id)`, s.schema),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.refresh_tokens (
			hash TEXT PRIMARY KEY,
			token_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			family_id TEXT NOT NULL,
			sequence BIGINT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			consumed_at TIMESTAMPTZ NULL,
			revoked_at TIMESTAMPTZ NULL
		)`, s.schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON %s.refresh_tokens(session_id)`, s.schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON %s.refresh_tokens(family_id)`, s.schema),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.session_events (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			occurred_at TIMESTAMPTZ NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb
		)`, s.schema),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_session_events_user_id_occurred_at ON %s.session_events(user_id, occurred_at DESC)`, s.schema),
	}

	for _, stmt := range ddl {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, input sessionstore.CreateSessionInput) (sessionstore.CreateSessionResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionstore.CreateSessionResult{}, err
	}
	defer rollback(tx)

	if err := s.expireSessionsTx(ctx, tx, input.Now, input.TrackHistory); err != nil {
		return sessionstore.CreateSessionResult{}, err
	}

	activeUser, err := s.listActiveSessionsTx(ctx, tx, input.Session.UserID, "")
	if err != nil {
		return sessionstore.CreateSessionResult{}, err
	}
	if input.MaxActiveSessionsPerUser > 0 && len(activeUser) >= input.MaxActiveSessionsPerUser && input.LimitBehavior == sessionconfig.LimitRejectNew {
		if input.TrackHistory {
			_ = s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
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

	activeDevice, err := s.listActiveSessionsTx(ctx, tx, input.Session.UserID, input.Session.DeviceID)
	if err != nil {
		return sessionstore.CreateSessionResult{}, err
	}
	if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" && len(activeDevice) >= input.MaxActiveSessionsPerDevice && input.LimitBehavior == sessionconfig.LimitRejectNew {
		if input.TrackHistory {
			_ = s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
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

	evicted := make([]sessionstore.Session, 0, 2)
	if input.MaxActiveSessionsPerUser > 0 {
		for len(activeUser) >= input.MaxActiveSessionsPerUser {
			oldest := activeUser[0]
			oldest.Status = sessionstore.StatusReplaced
			oldest.UpdatedAt = input.Now
			oldest.RevokedAt = timePointer(input.Now)
			oldest.TerminationReason = "evicted"
			oldest.ReplacementSessionID = input.Session.ID
			if err := s.updateSessionTx(ctx, tx, oldest); err != nil {
				return sessionstore.CreateSessionResult{}, err
			}
			if err := s.revokeFamilyTx(ctx, tx, oldest.RefreshFamilyID, input.Now); err != nil {
				return sessionstore.CreateSessionResult{}, err
			}
			if input.TrackHistory {
				if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
					ID:         oldest.ID + ":evicted",
					SessionID:  oldest.ID,
					UserID:     oldest.UserID,
					Type:       sessionstore.EventSessionEvicted,
					OccurredAt: input.Now,
					Reason:     "evicted_by_session_limit",
					IPAddress:  oldest.IPAddress,
					UserAgent:  oldest.UserAgent,
				}); err != nil {
					return sessionstore.CreateSessionResult{}, err
				}
			}
			evicted = append(evicted, oldest)
			activeUser = activeUser[1:]
		}
	}
	if input.MaxActiveSessionsPerDevice > 0 && input.Session.DeviceID != "" {
		for len(activeDevice) >= input.MaxActiveSessionsPerDevice {
			oldest := activeDevice[0]
			oldest.Status = sessionstore.StatusReplaced
			oldest.UpdatedAt = input.Now
			oldest.RevokedAt = timePointer(input.Now)
			oldest.TerminationReason = "evicted"
			oldest.ReplacementSessionID = input.Session.ID
			if err := s.updateSessionTx(ctx, tx, oldest); err != nil {
				return sessionstore.CreateSessionResult{}, err
			}
			if err := s.revokeFamilyTx(ctx, tx, oldest.RefreshFamilyID, input.Now); err != nil {
				return sessionstore.CreateSessionResult{}, err
			}
			if input.TrackHistory {
				if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
					ID:         oldest.ID + ":evicted:" + input.Session.ID,
					SessionID:  oldest.ID,
					UserID:     oldest.UserID,
					Type:       sessionstore.EventSessionEvicted,
					OccurredAt: input.Now,
					Reason:     "evicted_by_device_limit",
					IPAddress:  oldest.IPAddress,
					UserAgent:  oldest.UserAgent,
				}); err != nil {
					return sessionstore.CreateSessionResult{}, err
				}
			}
			activeDevice = activeDevice[1:]
		}
	}

	if err := s.insertSessionTx(ctx, tx, input.Session); err != nil {
		return sessionstore.CreateSessionResult{}, err
	}
	if err := s.insertRefreshTokenTx(ctx, tx, input.RefreshToken); err != nil {
		return sessionstore.CreateSessionResult{}, err
	}
	if input.TrackHistory {
		if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
			ID:         input.Session.ID + ":created",
			SessionID:  input.Session.ID,
			UserID:     input.Session.UserID,
			Type:       sessionstore.EventSessionCreated,
			OccurredAt: input.Now,
			Reason:     "created",
			IPAddress:  input.Session.IPAddress,
			UserAgent:  input.Session.UserAgent,
			Metadata:   cloneMap(input.Session.Metadata),
		}); err != nil {
			return sessionstore.CreateSessionResult{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return sessionstore.CreateSessionResult{}, err
	}

	return sessionstore.CreateSessionResult{
		Session:         input.Session,
		EvictedSessions: evicted,
	}, nil
}

func (s *Store) RefreshSession(ctx context.Context, input sessionstore.RefreshSessionInput) (sessionstore.RefreshSessionResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}
	defer rollback(tx)

	if err := s.expireSessionsTx(ctx, tx, input.Now, input.TrackHistory); err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}

	refreshToken, err := s.getRefreshTokenTx(ctx, tx, input.PresentedTokenHash, true)
	if err != nil {
		if errors.Is(err, sessionstore.ErrNotFound) {
			return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}, nil
		}
		return sessionstore.RefreshSessionResult{}, err
	}
	if refreshToken.RevokedAt != nil || refreshToken.ConsumedAt != nil {
		if input.RevokeFamilyOnRefreshReplay {
			if err := s.revokeFamilyTx(ctx, tx, refreshToken.FamilyID, input.Now); err != nil {
				return sessionstore.RefreshSessionResult{}, err
			}
		}
		if input.TrackHistory {
			_ = s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
				ID:         refreshToken.SessionID + ":replay:" + refreshToken.TokenID,
				SessionID:  refreshToken.SessionID,
				UserID:     refreshToken.UserID,
				Type:       sessionstore.EventRefreshReplay,
				OccurredAt: input.Now,
				Reason:     "refresh_replay_detected",
				IPAddress:  input.IPAddress,
				UserAgent:  input.UserAgent,
			})
		}
		if err := tx.Commit(); err != nil {
			return sessionstore.RefreshSessionResult{}, err
		}
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionReplayed}, nil
	}
	if input.Now.After(refreshToken.ExpiresAt) {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionExpired}, nil
	}

	sessionRecord, err := s.getSessionTx(ctx, tx, refreshToken.SessionID, true)
	if err != nil {
		if errors.Is(err, sessionstore.ErrNotFound) {
			return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInvalid}, nil
		}
		return sessionstore.RefreshSessionResult{}, err
	}
	sessionRecord = normalizeSession(sessionRecord, input.Now)
	if sessionRecord.Status != sessionstore.StatusActive {
		return sessionstore.RefreshSessionResult{Status: sessionstore.RefreshSessionInactive}, nil
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

	refreshToken.ConsumedAt = timePointer(input.Now)
	if err := s.upsertRefreshTokenTx(ctx, tx, refreshToken); err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}

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
	if err := s.updateSessionTx(ctx, tx, sessionRecord); err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}

	nextRefresh := sessionstore.RefreshToken{
		Hash:      input.NewRefreshTokenHash,
		TokenID:   input.NewRefreshTokenID,
		SessionID: sessionRecord.ID,
		UserID:    sessionRecord.UserID,
		FamilyID:  refreshToken.FamilyID,
		Sequence:  refreshToken.Sequence + 1,
		CreatedAt: input.Now,
		ExpiresAt: input.RefreshExpiresAt,
	}
	if err := s.insertRefreshTokenTx(ctx, tx, nextRefresh); err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}
	if input.TrackHistory {
		if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
			ID:         sessionRecord.ID + ":refresh:" + input.NewRefreshTokenID,
			SessionID:  sessionRecord.ID,
			UserID:     sessionRecord.UserID,
			Type:       sessionstore.EventSessionRefreshed,
			OccurredAt: input.Now,
			Reason:     "rotated_refresh_token",
			IPAddress:  sessionRecord.IPAddress,
			UserAgent:  sessionRecord.UserAgent,
		}); err != nil {
			return sessionstore.RefreshSessionResult{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return sessionstore.RefreshSessionResult{}, err
	}
	return sessionstore.RefreshSessionResult{
		Status:  sessionstore.RefreshSessionSuccess,
		Session: sessionRecord,
	}, nil
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (sessionstore.Session, error) {
	return s.getSessionTx(ctx, s.db, sessionID, false)
}

func (s *Store) ListActiveSessions(ctx context.Context, userID string) ([]sessionstore.Session, error) {
	return s.listActiveSessionsTx(ctx, s.db, userID, "")
}

func (s *Store) ListSessionEvents(ctx context.Context, userID string, query sessionstore.HistoryQuery) ([]sessionstore.SessionEvent, error) {
	var (
		builder strings.Builder
		args    []any
	)

	builder.WriteString(`SELECT id, session_id, user_id, type, occurred_at, reason, ip_address, user_agent, metadata
		FROM ` + s.qualify("session_events") + ` WHERE user_id = $1`)
	args = append(args, userID)
	if query.Since != nil {
		args = append(args, *query.Since)
		builder.WriteString(fmt.Sprintf(" AND occurred_at >= $%d", len(args)))
	}
	if query.Until != nil {
		args = append(args, *query.Until)
		builder.WriteString(fmt.Sprintf(" AND occurred_at <= $%d", len(args)))
	}
	builder.WriteString(" ORDER BY occurred_at DESC")
	if query.Limit > 0 {
		args = append(args, query.Limit)
		builder.WriteString(fmt.Sprintf(" LIMIT $%d", len(args)))
	}
	if query.Offset > 0 {
		args = append(args, query.Offset)
		builder.WriteString(fmt.Sprintf(" OFFSET $%d", len(args)))
	}

	rows, err := s.db.QueryContext(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]sessionstore.SessionEvent, 0)
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, input sessionstore.RevokeSessionInput) (sessionstore.Session, error) {
	return s.updateSessionStatus(ctx, input.SessionID, input.Now, input.Reason, sessionstore.StatusRevoked, sessionstore.EventSessionRevoked, input.TrackHistory)
}

func (s *Store) RevokeSessionsByUser(ctx context.Context, input sessionstore.RevokeSessionsByUserInput) ([]sessionstore.Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)

	sessions, err := s.listActiveSessionsTx(ctx, tx, input.UserID, "")
	if err != nil {
		return nil, err
	}
	updated := make([]sessionstore.Session, 0, len(sessions))
	for _, sessionRecord := range sessions {
		if sessionRecord.ID == input.ExceptSessionID {
			continue
		}
		sessionRecord.Status = sessionstore.StatusRevoked
		sessionRecord.RevokedAt = timePointer(input.Now)
		sessionRecord.TerminationReason = input.Reason
		sessionRecord.UpdatedAt = input.Now
		if err := s.updateSessionTx(ctx, tx, sessionRecord); err != nil {
			return nil, err
		}
		if err := s.revokeFamilyTx(ctx, tx, sessionRecord.RefreshFamilyID, input.Now); err != nil {
			return nil, err
		}
		if input.TrackHistory {
			if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
				ID:         sessionRecord.ID + ":revoked:" + input.Now.Format(time.RFC3339Nano),
				SessionID:  sessionRecord.ID,
				UserID:     sessionRecord.UserID,
				Type:       sessionstore.EventSessionRevoked,
				OccurredAt: input.Now,
				Reason:     input.Reason,
				IPAddress:  sessionRecord.IPAddress,
				UserAgent:  sessionRecord.UserAgent,
			}); err != nil {
				return nil, err
			}
		}
		updated = append(updated, sessionRecord)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *Store) DisableSession(ctx context.Context, input sessionstore.DisableSessionInput) (sessionstore.Session, error) {
	return s.updateSessionStatus(ctx, input.SessionID, input.Now, input.Reason, sessionstore.StatusDisabled, sessionstore.EventSessionDisabled, input.TrackHistory)
}

func (s *Store) updateSessionStatus(ctx context.Context, sessionID string, now time.Time, reason string, status sessionstore.Status, eventType sessionstore.EventType, trackHistory bool) (sessionstore.Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sessionstore.Session{}, err
	}
	defer rollback(tx)

	sessionRecord, err := s.getSessionTx(ctx, tx, sessionID, true)
	if err != nil {
		return sessionstore.Session{}, err
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
		if err := s.updateSessionTx(ctx, tx, sessionRecord); err != nil {
			return sessionstore.Session{}, err
		}
		if err := s.revokeFamilyTx(ctx, tx, sessionRecord.RefreshFamilyID, now); err != nil {
			return sessionstore.Session{}, err
		}
		if trackHistory {
			if err := s.insertEventTx(ctx, tx, sessionstore.SessionEvent{
				ID:         sessionRecord.ID + ":" + string(eventType) + ":" + now.Format(time.RFC3339Nano),
				SessionID:  sessionRecord.ID,
				UserID:     sessionRecord.UserID,
				Type:       eventType,
				OccurredAt: now,
				Reason:     reason,
				IPAddress:  sessionRecord.IPAddress,
				UserAgent:  sessionRecord.UserAgent,
			}); err != nil {
				return sessionstore.Session{}, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return sessionstore.Session{}, err
	}
	return sessionRecord, nil
}

func (s *Store) expireSessionsTx(ctx context.Context, db runner, now time.Time, trackHistory bool) error {
	rows, err := db.QueryContext(ctx, `UPDATE `+s.qualify("sessions")+`
		SET status = $1, termination_reason = $2, updated_at = $3
		WHERE status = $4 AND (absolute_expires_at <= $3 OR refresh_expires_at <= $3 OR idle_expires_at <= $3)
		RETURNING id, user_id, status, created_at, updated_at, last_seen_at, access_expires_at, refresh_expires_at, idle_expires_at,
		          absolute_expires_at, revoked_at, disabled_at, termination_reason, replacement_session_id, device_id, device_name,
		          platform, ip_address, user_agent, access_token_version, refresh_family_id, current_refresh_token_id, current_refresh_token_hash,
		          claims, metadata`,
		sessionstore.StatusExpired, "expired", now, sessionstore.StatusActive)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		sessionRecord, scanErr := scanSession(rows)
		if scanErr != nil {
			return scanErr
		}
		if err := s.revokeFamilyTx(ctx, db, sessionRecord.RefreshFamilyID, now); err != nil {
			return err
		}
		if trackHistory {
			if err := s.insertEventTx(ctx, db, sessionstore.SessionEvent{
				ID:         sessionRecord.ID + ":expired",
				SessionID:  sessionRecord.ID,
				UserID:     sessionRecord.UserID,
				Type:       sessionstore.EventSessionExpired,
				OccurredAt: now,
				Reason:     "expired",
				IPAddress:  sessionRecord.IPAddress,
				UserAgent:  sessionRecord.UserAgent,
			}); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}

func (s *Store) revokeFamilyTx(ctx context.Context, db runner, familyID string, now time.Time) error {
	_, err := db.ExecContext(ctx, `UPDATE `+s.qualify("refresh_tokens")+` SET revoked_at = COALESCE(revoked_at, $1) WHERE family_id = $2`, now, familyID)
	return err
}

func (s *Store) listActiveSessionsTx(ctx context.Context, db runner, userID string, deviceID string) ([]sessionstore.Session, error) {
	query := `SELECT id, user_id, status, created_at, updated_at, last_seen_at, access_expires_at, refresh_expires_at, idle_expires_at,
		          absolute_expires_at, revoked_at, disabled_at, termination_reason, replacement_session_id, device_id, device_name,
		          platform, ip_address, user_agent, access_token_version, refresh_family_id, current_refresh_token_id, current_refresh_token_hash,
		          claims, metadata
			FROM ` + s.qualify("sessions") + ` WHERE user_id = $1 AND status = $2`
	args := []any{userID, sessionstore.StatusActive}
	if deviceID != "" {
		args = append(args, deviceID)
		query += fmt.Sprintf(" AND device_id = $%d", len(args))
	}
	query += " ORDER BY created_at ASC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]sessionstore.Session, 0)
	for rows.Next() {
		sessionRecord, scanErr := scanSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, sessionRecord)
	}
	return out, rows.Err()
}

func (s *Store) getSessionTx(ctx context.Context, db runner, sessionID string, forUpdate bool) (sessionstore.Session, error) {
	query := `SELECT id, user_id, status, created_at, updated_at, last_seen_at, access_expires_at, refresh_expires_at, idle_expires_at,
		          absolute_expires_at, revoked_at, disabled_at, termination_reason, replacement_session_id, device_id, device_name,
		          platform, ip_address, user_agent, access_token_version, refresh_family_id, current_refresh_token_id, current_refresh_token_hash,
		          claims, metadata
			FROM ` + s.qualify("sessions") + ` WHERE id = $1`
	if forUpdate {
		query += " FOR UPDATE"
	}

	row := db.QueryRowContext(ctx, query, sessionID)
	sessionRecord, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sessionstore.Session{}, sessionstore.ErrNotFound
		}
		return sessionstore.Session{}, err
	}
	return sessionRecord, nil
}

func (s *Store) getRefreshTokenTx(ctx context.Context, db runner, hash string, forUpdate bool) (sessionstore.RefreshToken, error) {
	query := `SELECT hash, token_id, session_id, user_id, family_id, sequence, created_at, expires_at, consumed_at, revoked_at
		FROM ` + s.qualify("refresh_tokens") + ` WHERE hash = $1`
	if forUpdate {
		query += " FOR UPDATE"
	}

	row := db.QueryRowContext(ctx, query, hash)
	refreshToken, err := scanRefreshToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sessionstore.RefreshToken{}, sessionstore.ErrNotFound
		}
		return sessionstore.RefreshToken{}, err
	}
	return refreshToken, nil
}

func (s *Store) insertSessionTx(ctx context.Context, db runner, sessionRecord sessionstore.Session) error {
	claims, metadata, err := marshalMaps(sessionRecord.Claims, sessionRecord.Metadata)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO `+s.qualify("sessions")+`
		(id, user_id, status, created_at, updated_at, last_seen_at, access_expires_at, refresh_expires_at, idle_expires_at, absolute_expires_at,
		 revoked_at, disabled_at, termination_reason, replacement_session_id, device_id, device_name, platform, ip_address, user_agent,
		 access_token_version, refresh_family_id, current_refresh_token_id, current_refresh_token_hash, claims, metadata)
		VALUES
		($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
		sessionRecord.ID, sessionRecord.UserID, sessionRecord.Status, sessionRecord.CreatedAt, sessionRecord.UpdatedAt, sessionRecord.LastSeenAt,
		sessionRecord.AccessExpiresAt, sessionRecord.RefreshExpiresAt, sessionRecord.IdleExpiresAt, sessionRecord.AbsoluteExpiresAt,
		sessionRecord.RevokedAt, sessionRecord.DisabledAt, sessionRecord.TerminationReason, sessionRecord.ReplacementSessionID, sessionRecord.DeviceID,
		sessionRecord.DeviceName, sessionRecord.Platform, sessionRecord.IPAddress, sessionRecord.UserAgent, sessionRecord.AccessTokenVersion,
		sessionRecord.RefreshFamilyID, sessionRecord.CurrentRefreshTokenID, sessionRecord.CurrentRefreshTokenHash, claims, metadata)
	return err
}

func (s *Store) updateSessionTx(ctx context.Context, db runner, sessionRecord sessionstore.Session) error {
	claims, metadata, err := marshalMaps(sessionRecord.Claims, sessionRecord.Metadata)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE `+s.qualify("sessions")+`
		SET user_id=$2, status=$3, created_at=$4, updated_at=$5, last_seen_at=$6, access_expires_at=$7, refresh_expires_at=$8, idle_expires_at=$9,
		    absolute_expires_at=$10, revoked_at=$11, disabled_at=$12, termination_reason=$13, replacement_session_id=$14, device_id=$15,
		    device_name=$16, platform=$17, ip_address=$18, user_agent=$19, access_token_version=$20, refresh_family_id=$21,
		    current_refresh_token_id=$22, current_refresh_token_hash=$23, claims=$24, metadata=$25
		WHERE id=$1`,
		sessionRecord.ID, sessionRecord.UserID, sessionRecord.Status, sessionRecord.CreatedAt, sessionRecord.UpdatedAt, sessionRecord.LastSeenAt,
		sessionRecord.AccessExpiresAt, sessionRecord.RefreshExpiresAt, sessionRecord.IdleExpiresAt, sessionRecord.AbsoluteExpiresAt,
		sessionRecord.RevokedAt, sessionRecord.DisabledAt, sessionRecord.TerminationReason, sessionRecord.ReplacementSessionID, sessionRecord.DeviceID,
		sessionRecord.DeviceName, sessionRecord.Platform, sessionRecord.IPAddress, sessionRecord.UserAgent, sessionRecord.AccessTokenVersion,
		sessionRecord.RefreshFamilyID, sessionRecord.CurrentRefreshTokenID, sessionRecord.CurrentRefreshTokenHash, claims, metadata)
	return err
}

func (s *Store) insertRefreshTokenTx(ctx context.Context, db runner, refreshToken sessionstore.RefreshToken) error {
	_, err := db.ExecContext(ctx, `INSERT INTO `+s.qualify("refresh_tokens")+`
		(hash, token_id, session_id, user_id, family_id, sequence, created_at, expires_at, consumed_at, revoked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		refreshToken.Hash, refreshToken.TokenID, refreshToken.SessionID, refreshToken.UserID, refreshToken.FamilyID, refreshToken.Sequence,
		refreshToken.CreatedAt, refreshToken.ExpiresAt, refreshToken.ConsumedAt, refreshToken.RevokedAt)
	return err
}

func (s *Store) upsertRefreshTokenTx(ctx context.Context, db runner, refreshToken sessionstore.RefreshToken) error {
	_, err := db.ExecContext(ctx, `UPDATE `+s.qualify("refresh_tokens")+`
		SET token_id=$2, session_id=$3, user_id=$4, family_id=$5, sequence=$6, created_at=$7, expires_at=$8, consumed_at=$9, revoked_at=$10
		WHERE hash=$1`,
		refreshToken.Hash, refreshToken.TokenID, refreshToken.SessionID, refreshToken.UserID, refreshToken.FamilyID, refreshToken.Sequence,
		refreshToken.CreatedAt, refreshToken.ExpiresAt, refreshToken.ConsumedAt, refreshToken.RevokedAt)
	return err
}

func (s *Store) insertEventTx(ctx context.Context, db runner, event sessionstore.SessionEvent) error {
	metadata, err := json.Marshal(cloneMap(event.Metadata))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO `+s.qualify("session_events")+`
		(id, session_id, user_id, type, occurred_at, reason, ip_address, user_agent, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO NOTHING`,
		event.ID, event.SessionID, event.UserID, event.Type, event.OccurredAt, event.Reason, event.IPAddress, event.UserAgent, metadata)
	return err
}

func (s *Store) qualify(table string) string {
	if table == "" {
		return s.schema
	}
	return fmt.Sprintf("%s.%s", s.schema, table)
}

type scanner interface {
	Scan(dest ...any) error
}

type runner interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanSession(row scanner) (sessionstore.Session, error) {
	var (
		sessionRecord                      sessionstore.Session
		claimsJSON, metadataJSON           []byte
		revokedAt, disabledAt              sql.NullTime
		terminationReason, replacementID   string
		deviceID, deviceName, platform     string
		ipAddress, userAgent               string
		currentRefreshTokenID, currentHash string
	)
	err := row.Scan(
		&sessionRecord.ID, &sessionRecord.UserID, &sessionRecord.Status, &sessionRecord.CreatedAt, &sessionRecord.UpdatedAt, &sessionRecord.LastSeenAt,
		&sessionRecord.AccessExpiresAt, &sessionRecord.RefreshExpiresAt, &sessionRecord.IdleExpiresAt, &sessionRecord.AbsoluteExpiresAt,
		&revokedAt, &disabledAt, &terminationReason, &replacementID, &deviceID, &deviceName, &platform, &ipAddress, &userAgent,
		&sessionRecord.AccessTokenVersion, &sessionRecord.RefreshFamilyID, &currentRefreshTokenID, &currentHash, &claimsJSON, &metadataJSON,
	)
	if err != nil {
		return sessionstore.Session{}, err
	}
	sessionRecord.TerminationReason = terminationReason
	sessionRecord.ReplacementSessionID = replacementID
	sessionRecord.DeviceID = deviceID
	sessionRecord.DeviceName = deviceName
	sessionRecord.Platform = platform
	sessionRecord.IPAddress = ipAddress
	sessionRecord.UserAgent = userAgent
	sessionRecord.CurrentRefreshTokenID = currentRefreshTokenID
	sessionRecord.CurrentRefreshTokenHash = currentHash
	if revokedAt.Valid {
		sessionRecord.RevokedAt = timePointer(revokedAt.Time.UTC())
	}
	if disabledAt.Valid {
		sessionRecord.DisabledAt = timePointer(disabledAt.Time.UTC())
	}
	if len(claimsJSON) > 0 {
		_ = json.Unmarshal(claimsJSON, &sessionRecord.Claims)
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &sessionRecord.Metadata)
	}
	return sessionRecord, nil
}

func scanRefreshToken(row scanner) (sessionstore.RefreshToken, error) {
	var (
		refreshToken          sessionstore.RefreshToken
		consumedAt, revokedAt sql.NullTime
	)
	err := row.Scan(&refreshToken.Hash, &refreshToken.TokenID, &refreshToken.SessionID, &refreshToken.UserID, &refreshToken.FamilyID,
		&refreshToken.Sequence, &refreshToken.CreatedAt, &refreshToken.ExpiresAt, &consumedAt, &revokedAt)
	if err != nil {
		return sessionstore.RefreshToken{}, err
	}
	if consumedAt.Valid {
		refreshToken.ConsumedAt = timePointer(consumedAt.Time.UTC())
	}
	if revokedAt.Valid {
		refreshToken.RevokedAt = timePointer(revokedAt.Time.UTC())
	}
	return refreshToken, nil
}

func scanEvent(row scanner) (sessionstore.SessionEvent, error) {
	var (
		event        sessionstore.SessionEvent
		metadataJSON []byte
	)
	err := row.Scan(&event.ID, &event.SessionID, &event.UserID, &event.Type, &event.OccurredAt, &event.Reason, &event.IPAddress, &event.UserAgent, &metadataJSON)
	if err != nil {
		return sessionstore.SessionEvent{}, err
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &event.Metadata)
	}
	return event, nil
}

func marshalMaps(claims map[string]any, metadata map[string]any) ([]byte, []byte, error) {
	claimsJSON, err := json.Marshal(cloneMap(claims))
	if err != nil {
		return nil, nil, err
	}
	metadataJSON, err := json.Marshal(cloneMap(metadata))
	if err != nil {
		return nil, nil, err
	}
	return claimsJSON, metadataJSON, nil
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
	value := t.UTC()
	return &value
}

func rollback(tx *sql.Tx) {
	_ = tx.Rollback()
}
