package store

import (
	"context"
	"errors"
	"time"

	"github.com/nakhostin/gox/session/config"
)

var (
	ErrNotFound           = errors.New("store: not found")
	ErrActiveSessionLimit = errors.New("store: active session limit reached")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusRevoked  Status = "revoked"
	StatusDisabled Status = "disabled"
	StatusExpired  Status = "expired"
	StatusReplaced Status = "replaced"
)

type EventType string

const (
	EventSessionCreated       EventType = "session_created"
	EventSessionRefreshed     EventType = "session_refreshed"
	EventSessionRevoked       EventType = "session_revoked"
	EventSessionDisabled      EventType = "session_disabled"
	EventSessionEvicted       EventType = "session_evicted"
	EventLogout               EventType = "session_logout"
	EventRefreshReplay        EventType = "refresh_replay_detected"
	EventLoginRejectedByLimit EventType = "login_rejected_by_limit"
	EventSessionExpired       EventType = "session_expired"
)

type RefreshSessionStatus string

const (
	RefreshSessionSuccess  RefreshSessionStatus = "success"
	RefreshSessionInvalid  RefreshSessionStatus = "invalid"
	RefreshSessionExpired  RefreshSessionStatus = "expired"
	RefreshSessionReplayed RefreshSessionStatus = "replayed"
	RefreshSessionInactive RefreshSessionStatus = "inactive"
)

type HistoryQuery struct {
	Limit  int
	Offset int
	Since  *time.Time
	Until  *time.Time
}

type Session struct {
	ID                      string
	UserID                  string
	Status                  Status
	CreatedAt               time.Time
	UpdatedAt               time.Time
	LastSeenAt              time.Time
	AccessExpiresAt         time.Time
	RefreshExpiresAt        time.Time
	IdleExpiresAt           time.Time
	AbsoluteExpiresAt       time.Time
	RevokedAt               *time.Time
	DisabledAt              *time.Time
	TerminationReason       string
	ReplacementSessionID    string
	DeviceID                string
	DeviceName              string
	Platform                string
	IPAddress               string
	UserAgent               string
	AccessTokenVersion      int64
	RefreshFamilyID         string
	CurrentRefreshTokenID   string
	CurrentRefreshTokenHash string
	Claims                  map[string]any
	Metadata                map[string]any
}

type RefreshToken struct {
	Hash       string
	TokenID    string
	SessionID  string
	UserID     string
	FamilyID   string
	Sequence   int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	RevokedAt  *time.Time
}

type SessionEvent struct {
	ID         string
	SessionID  string
	UserID     string
	Type       EventType
	OccurredAt time.Time
	Reason     string
	IPAddress  string
	UserAgent  string
	Metadata   map[string]any
}

type CreateSessionInput struct {
	Now                        time.Time
	Session                    Session
	RefreshToken               RefreshToken
	MaxActiveSessionsPerUser   int
	MaxActiveSessionsPerDevice int
	LimitBehavior              config.LimitBehavior
	TrackHistory               bool
}

type CreateSessionResult struct {
	Session         Session
	EvictedSessions []Session
}

type RefreshSessionInput struct {
	Now                         time.Time
	PresentedTokenHash          string
	NewRefreshTokenHash         string
	NewRefreshTokenID           string
	AccessExpiresAt             time.Time
	RefreshExpiresAt            time.Time
	IdleExpiresAt               time.Time
	IPAddress                   string
	UserAgent                   string
	TrackHistory                bool
	RevokeFamilyOnRefreshReplay bool
}

type RefreshSessionResult struct {
	Status  RefreshSessionStatus
	Session Session
}

type RevokeSessionInput struct {
	Now          time.Time
	SessionID    string
	Reason       string
	TrackHistory bool
}

type RevokeSessionsByUserInput struct {
	Now             time.Time
	UserID          string
	ExceptSessionID string
	Reason          string
	TrackHistory    bool
}

type DisableSessionInput struct {
	Now          time.Time
	SessionID    string
	Reason       string
	TrackHistory bool
}

type Store interface {
	CreateSession(ctx context.Context, input CreateSessionInput) (CreateSessionResult, error)
	RefreshSession(ctx context.Context, input RefreshSessionInput) (RefreshSessionResult, error)
	GetSession(ctx context.Context, sessionID string) (Session, error)
	ListActiveSessions(ctx context.Context, userID string) ([]Session, error)
	ListSessionEvents(ctx context.Context, userID string, query HistoryQuery) ([]SessionEvent, error)
	RevokeSession(ctx context.Context, input RevokeSessionInput) (Session, error)
	RevokeSessionsByUser(ctx context.Context, input RevokeSessionsByUserInput) ([]Session, error)
	DisableSession(ctx context.Context, input DisableSessionInput) (Session, error)
}
