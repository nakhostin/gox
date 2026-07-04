package config

import "time"

type LimitBehavior string

const (
	LimitRejectNew         LimitBehavior = "reject_new"
	LimitEvictOldest       LimitBehavior = "evict_oldest"
	LimitEvictOldestDevice LimitBehavior = "evict_oldest_same_device"
)

type Config struct {
	prefix                      string
	refreshTokenSecret          string
	refreshTokenLength          int
	accessTokenTTL              time.Duration
	refreshTokenTTL             time.Duration
	idleTimeout                 time.Duration
	absoluteTTL                 time.Duration
	maxActiveSessionsPerUser    int
	maxActiveSessionsPerDevice  int
	limitBehavior               LimitBehavior
	trackHistory                bool
	revokeFamilyOnRefreshReplay bool
}

func New() *Config {
	return &Config{
		prefix:                      "gox:sessions",
		refreshTokenSecret:          "gox-session-refresh-secret",
		refreshTokenLength:          48,
		accessTokenTTL:              15 * time.Minute,
		refreshTokenTTL:             30 * 24 * time.Hour,
		idleTimeout:                 7 * 24 * time.Hour,
		absoluteTTL:                 90 * 24 * time.Hour,
		maxActiveSessionsPerUser:    5,
		maxActiveSessionsPerDevice:  2,
		limitBehavior:               LimitEvictOldest,
		trackHistory:                true,
		revokeFamilyOnRefreshReplay: true,
	}
}

func (c *Config) WithPrefix(prefix string) *Config {
	c.prefix = prefix
	return c
}

func (c *Config) WithRefreshTokenSecret(secret string) *Config {
	c.refreshTokenSecret = secret
	return c
}

func (c *Config) WithRefreshTokenLength(length int) *Config {
	c.refreshTokenLength = length
	return c
}

func (c *Config) WithAccessTokenTTL(ttl time.Duration) *Config {
	c.accessTokenTTL = ttl
	return c
}

func (c *Config) WithRefreshTokenTTL(ttl time.Duration) *Config {
	c.refreshTokenTTL = ttl
	return c
}

func (c *Config) WithIdleTimeout(timeout time.Duration) *Config {
	c.idleTimeout = timeout
	return c
}

func (c *Config) WithAbsoluteTTL(ttl time.Duration) *Config {
	c.absoluteTTL = ttl
	return c
}

func (c *Config) WithMaxActiveSessionsPerUser(limit int) *Config {
	c.maxActiveSessionsPerUser = limit
	return c
}

func (c *Config) WithMaxActiveSessionsPerDevice(limit int) *Config {
	c.maxActiveSessionsPerDevice = limit
	return c
}

func (c *Config) WithLimitBehavior(behavior LimitBehavior) *Config {
	c.limitBehavior = behavior
	return c
}

func (c *Config) WithTrackHistory(track bool) *Config {
	c.trackHistory = track
	return c
}

func (c *Config) WithRevokeFamilyOnRefreshReplay(revoke bool) *Config {
	c.revokeFamilyOnRefreshReplay = revoke
	return c
}

func (c *Config) Build() Config {
	return *c
}

func (c Config) GetPrefix() string {
	return c.prefix
}

func (c Config) GetRefreshTokenSecret() string {
	return c.refreshTokenSecret
}

func (c Config) GetRefreshTokenLength() int {
	return c.refreshTokenLength
}

func (c Config) GetAccessTokenTTL() time.Duration {
	return c.accessTokenTTL
}

func (c Config) GetRefreshTokenTTL() time.Duration {
	return c.refreshTokenTTL
}

func (c Config) GetIdleTimeout() time.Duration {
	return c.idleTimeout
}

func (c Config) GetAbsoluteTTL() time.Duration {
	return c.absoluteTTL
}

func (c Config) GetMaxActiveSessionsPerUser() int {
	return c.maxActiveSessionsPerUser
}

func (c Config) GetMaxActiveSessionsPerDevice() int {
	return c.maxActiveSessionsPerDevice
}

func (c Config) GetLimitBehavior() LimitBehavior {
	return c.limitBehavior
}

func (c Config) GetTrackHistory() bool {
	return c.trackHistory
}

func (c Config) GetRevokeFamilyOnRefreshReplay() bool {
	return c.revokeFamilyOnRefreshReplay
}
