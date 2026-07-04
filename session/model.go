package session

import (
	sessionconfig "github.com/nakhostin/gox/session/config"
	sessionstore "github.com/nakhostin/gox/session/store"
	sessiontoken "github.com/nakhostin/gox/session/token"
)

type Store = sessionstore.Store

type Session = sessionstore.Session
type SessionEvent = sessionstore.SessionEvent
type HistoryQuery = sessionstore.HistoryQuery
type Status = sessionstore.Status
type EventType = sessionstore.EventType
type Claims = sessiontoken.Claims
type LimitBehavior = sessionconfig.LimitBehavior

const (
	StatusActive   = sessionstore.StatusActive
	StatusRevoked  = sessionstore.StatusRevoked
	StatusDisabled = sessionstore.StatusDisabled
	StatusExpired  = sessionstore.StatusExpired
	StatusReplaced = sessionstore.StatusReplaced

	EventSessionCreated       = sessionstore.EventSessionCreated
	EventSessionRefreshed     = sessionstore.EventSessionRefreshed
	EventSessionRevoked       = sessionstore.EventSessionRevoked
	EventSessionDisabled      = sessionstore.EventSessionDisabled
	EventSessionEvicted       = sessionstore.EventSessionEvicted
	EventLogout               = sessionstore.EventLogout
	EventRefreshReplay        = sessionstore.EventRefreshReplay
	EventLoginRejectedByLimit = sessionstore.EventLoginRejectedByLimit
	EventSessionExpired       = sessionstore.EventSessionExpired

	LimitRejectNew         = sessionconfig.LimitRejectNew
	LimitEvictOldest       = sessionconfig.LimitEvictOldest
	LimitEvictOldestDevice = sessionconfig.LimitEvictOldestDevice
)

type CreateInput struct {
	UserID     string
	DeviceID   string
	DeviceName string
	Platform   string
	IPAddress  string
	UserAgent  string
	Claims     map[string]any
	Metadata   map[string]any
}

type CreateResult struct {
	Session      Session
	AccessToken  string
	RefreshToken string
}

type RefreshInput struct {
	RefreshToken string
	IPAddress    string
	UserAgent    string
}

type RefreshResult struct {
	Session      Session
	AccessToken  string
	RefreshToken string
}
