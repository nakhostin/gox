# gox/session

`gox/session` is a reusable Go package for managing user sessions with support for:

- access token issuance and validation
- refresh token rotation
- active session limits per user and per device
- automatic eviction or rejection when limits are reached
- session revocation and disabling
- session history and audit events
- pluggable storage backends
- pluggable access-token providers

The package is designed as a standalone module, so you can import it directly into another project and choose the storage and token strategy that fits your application.

## Features

- Standalone importable module: `github.com/nakhostin/gox/session`
- Public service API focused on domain actions instead of raw CRUD
- Configurable session limits and expiration policies
- Refresh tokens are always opaque and stored only as hashes
- Access tokens can be issued using:
  - `JWT`
  - `PASETO`
  - `opaque`
- Storage backends:
  - in-memory store
  - Redis store
  - PostgreSQL store
- Session lifecycle states:
  - `active`
  - `revoked`
  - `disabled`
  - `expired`
  - `replaced`
- Built-in history events for create, refresh, revoke, disable, eviction, replay detection, and expiration

## Installation

```bash
go get github.com/nakhostin/gox/session
```

If you use the Redis or PostgreSQL backends, make sure your project also includes the appropriate dependencies and database driver.

## Package Layout

```text
session/
  config/
  example/
  store/
    memory/
    redis/
    postgres/
  token/
    jwt/
    paseto/
    opaque/
  errors.go
  model.go
  options.go
  service.go
```

## Core API

The main entry point is `session.New(...)`:

```go
svc := session.New(cfg, store, accessProvider, refreshProvider, opts...)
```

### Public Methods

- `Create`
- `Refresh`
- `ValidateAccessToken`
- `Get`
- `ListActive`
- `ListHistory`
- `Revoke`
- `RevokeAll`
- `RevokeOthers`
- `Disable`

## Quick Start

The following example uses the in-memory store and the JWT access-token provider.

```go
package main

import (
	"context"
	"time"

	"github.com/nakhostin/gox/session"
	"github.com/nakhostin/gox/session/config"
	"github.com/nakhostin/gox/session/store/memory"
	jwttoken "github.com/nakhostin/gox/session/token/jwt"
)

func main() {
	ctx := context.Background()

	store := memory.New()

	accessProvider := jwttoken.New(jwttoken.Config{
		Secret: []byte("my-access-secret"),
		Issuer: "my-app",
	})

	cfg := config.New().
		WithPrefix("myapp:sessions").
		WithRefreshTokenSecret("my-refresh-secret").
		WithAccessTokenTTL(15 * time.Minute).
		WithRefreshTokenTTL(30 * 24 * time.Hour).
		WithIdleTimeout(7 * 24 * time.Hour).
		WithAbsoluteTTL(90 * 24 * time.Hour).
		WithMaxActiveSessionsPerUser(3).
		WithMaxActiveSessionsPerDevice(1).
		WithLimitBehavior(config.LimitEvictOldest).
		WithTrackHistory(true).
		WithRevokeFamilyOnRefreshReplay(true).
		Build()

	svc := session.New(cfg, store, accessProvider, nil)

	login, err := svc.Create(ctx, session.CreateInput{
		UserID:     "user-123",
		DeviceID:   "device-web-1",
		DeviceName: "Chrome on MacBook",
		Platform:   "web",
		IPAddress:  "127.0.0.1",
		UserAgent:  "Mozilla/5.0",
		Claims: map[string]any{
			"role": "admin",
		},
		Metadata: map[string]any{
			"app_version": "1.0.0",
		},
	})
	if err != nil {
		panic(err)
	}

	_, err = svc.ValidateAccessToken(ctx, login.AccessToken)
	if err != nil {
		panic(err)
	}

	_, err = svc.Refresh(ctx, session.RefreshInput{
		RefreshToken: login.RefreshToken,
		IPAddress:    "127.0.0.2",
		UserAgent:    "Mozilla/5.0 updated",
	})
	if err != nil {
		panic(err)
	}
}
```

A runnable sample is also available in `session/example/main.go`.

## Configuration

Create configuration with the builder in `session/config`.

```go
cfg := config.New().
	WithPrefix("myapp:sessions").
	WithRefreshTokenSecret("my-refresh-secret").
	WithRefreshTokenLength(48).
	WithAccessTokenTTL(15 * time.Minute).
	WithRefreshTokenTTL(30 * 24 * time.Hour).
	WithIdleTimeout(7 * 24 * time.Hour).
	WithAbsoluteTTL(90 * 24 * time.Hour).
	WithMaxActiveSessionsPerUser(5).
	WithMaxActiveSessionsPerDevice(2).
	WithLimitBehavior(config.LimitEvictOldest).
	WithTrackHistory(true).
	WithRevokeFamilyOnRefreshReplay(true).
	Build()
```

### Supported Configuration Options

- `WithPrefix(string)`
- `WithRefreshTokenSecret(string)`
- `WithRefreshTokenLength(int)`
- `WithAccessTokenTTL(time.Duration)`
- `WithRefreshTokenTTL(time.Duration)`
- `WithIdleTimeout(time.Duration)`
- `WithAbsoluteTTL(time.Duration)`
- `WithMaxActiveSessionsPerUser(int)`
- `WithMaxActiveSessionsPerDevice(int)`
- `WithLimitBehavior(config.LimitBehavior)`
- `WithTrackHistory(bool)`
- `WithRevokeFamilyOnRefreshReplay(bool)`

### Limit Behaviors

- `config.LimitRejectNew`
  Rejects the new login when the limit is reached.

- `config.LimitEvictOldest`
  Revokes/replaces the oldest active session and allows the new login.

- `config.LimitEvictOldestDevice`
  Reserved as a public behavior constant and exposed in the API surface.

## Session Lifecycle

Each session can move through one of the following states:

- `active`
- `revoked`
- `disabled`
- `expired`
- `replaced`

### Create

`Create` opens a new session, issues an access token, generates a refresh token, and enforces configured login limits.

### Refresh

`Refresh` rotates the refresh token and issues a fresh access token. If a previously used refresh token is presented again, replay detection is triggered and the token family can be revoked depending on configuration.

### Revoke

`Revoke` invalidates a single session.

### RevokeAll

`RevokeAll` invalidates all active sessions for a user.

### RevokeOthers

`RevokeOthers` invalidates all active sessions for a user except the current session.

### Disable

`Disable` marks a session as disabled and prevents further use.

## Data Models

The public API exposes these important models:

- `session.Session`
- `session.SessionEvent`
- `session.CreateInput`
- `session.CreateResult`
- `session.RefreshInput`
- `session.RefreshResult`
- `session.Claims`
- `session.HistoryQuery`

### `CreateInput`

```go
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
```

### `RefreshInput`

```go
type RefreshInput struct {
	RefreshToken string
	IPAddress    string
	UserAgent    string
}
```

## Access Token Providers

The package separates access-token logic behind a common interface in `session/token/provider.go`.

### JWT Provider

Import:

```go
import jwttoken "github.com/nakhostin/gox/session/token/jwt"
```

Usage:

```go
provider := jwttoken.New(jwttoken.Config{
	Secret:   []byte("jwt-secret"),
	Issuer:   "my-app",
	Audience: []string{"api"},
})
```

Notes:

- Uses HS256 signing.
- Custom claims are copied into JWT claims.

### PASETO Provider

Import:

```go
import pasetotoken "github.com/nakhostin/gox/session/token/paseto"
```

Usage:

```go
provider := pasetotoken.New(pasetotoken.Config{
	SymmetricKey: []byte("0123456789abcdef0123456789abcdef"),
	Issuer:       "my-app",
	Footer:       "my-footer",
})
```

Notes:

- Uses PASETO v2 local mode through a symmetric key.
- Custom values are serialized into the token payload.
- The symmetric key should be 32 bytes for the underlying implementation.

### Opaque Provider

Import:

```go
import opaquetoken "github.com/nakhostin/gox/session/token/opaque"
```

Usage:

```go
provider := opaquetoken.New(opaquetoken.Config{
	Secret: []byte("opaque-secret"),
})
```

Notes:

- Produces a signed opaque access token.
- Useful when you do not want JWT or PASETO formatting.

## Refresh Token Provider

The `refreshProvider` argument in `session.New(...)` is optional.

If you pass `nil`, the package uses the built-in `OpaqueRefreshProvider`, which generates random refresh tokens and stores only their HMAC hash.

```go
svc := session.New(cfg, store, accessProvider, nil)
```

## Storage Backends

The `Store` interface is defined in `session/store/store.go`.

### In-Memory Store

Import:

```go
import "github.com/nakhostin/gox/session/store/memory"
```

Usage:

```go
store := memory.New()
```

Best for:

- tests
- local development
- single-process environments

### Redis Store

Import:

```go
import redisstore "github.com/nakhostin/gox/session/store/redis"
```

Usage:

```go
rdb := redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

store := redisstore.New(rdb, "myapp:sessions")
```

Best for:

- fast active-session lookups
- TTL-based workloads
- distributed deployments that need shared session state

Implementation notes:

- Stores sessions, refresh-token records, and history indexes in Redis.
- Enforces limits through Redis transactions and watched keys.

### PostgreSQL Store

Import:

```go
import postgresstore "github.com/nakhostin/gox/session/store/postgres"
```

Usage:

```go
db, err := sql.Open("postgres", dsn)
if err != nil {
	panic(err)
}

store := postgresstore.New(db, "public")

if err := store.CreateSchema(context.Background()); err != nil {
	panic(err)
}
```

Best for:

- durable session storage
- audit-heavy systems
- applications that want SQL querying over sessions and events

Implementation notes:

- Creates `sessions`, `refresh_tokens`, and `session_events` tables.
- Uses transactions to enforce limits and rotate refresh tokens safely.
- Requires a PostgreSQL driver in your application, such as `github.com/lib/pq` or `github.com/jackc/pgx/v5/stdlib`.

## Listing Sessions And History

### List active sessions

```go
sessions, err := svc.ListActive(ctx, "user-123")
if err != nil {
	panic(err)
}
```

### List session history

```go
events, err := svc.ListHistory(ctx, "user-123", session.HistoryQuery{
	Limit: 20,
})
if err != nil {
	panic(err)
}
```

## Error Handling

Common exported errors:

- `session.ErrSessionNotFound`
- `session.ErrSessionInvalid`
- `session.ErrSessionExpired`
- `session.ErrSessionRevoked`
- `session.ErrSessionDisabled`
- `session.ErrRefreshTokenInvalid`
- `session.ErrRefreshTokenExpired`
- `session.ErrRefreshTokenReplayed`
- `session.ErrAccessTokenInvalid`
- `session.ErrAccessTokenExpired`
- `session.ErrMaxSessionsReached`
- `session.ErrInvalidConfiguration`
- `session.ErrInternal`

Example:

```go
result, err := svc.Refresh(ctx, session.RefreshInput{
	RefreshToken: token,
})
if err != nil {
	switch err {
	case session.ErrRefreshTokenExpired:
		// ask the user to log in again
	case session.ErrRefreshTokenReplayed:
		// trigger security response
	default:
		// generic error handling
	}
}
```

## Options

The package provides service options in `session/options.go`:

- `session.WithNowFunc(...)`
- `session.WithIDGenerator(...)`
- `session.WithRefreshTokenGenerator(...)`

These are mainly useful for:

- tests
- deterministic IDs
- custom time control
- custom refresh-token generation

## Testing

Run the package tests with:

```bash
go test ./...
```

## Security Notes

- Refresh tokens are never stored in raw form; only an HMAC hash is persisted.
- Replay detection is supported for rotated refresh tokens.
- Access tokens include session-aware fields such as `sub`, `sid`, `jti`, `iat`, and `exp`.
- Revocation behavior still depends on your application validating access tokens through the session service.

## Current Notes

- The in-memory store is the simplest reference implementation and is ideal for tests.
- The Redis store is optimized for shared session state, but still follows the same domain contract as the other backends.
- The PostgreSQL store includes a `CreateSchema` helper for bootstrapping tables.
- If you use `PASETO`, make sure your symmetric key length is valid for the underlying library.

## License

This package follows the license of the parent repository.
