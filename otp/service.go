package otp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nakhostin/gox/otp/config"
	"github.com/redis/go-redis/v9"
)

var (
	ErrExpired = errors.New("expired")
	ErrInvalid = errors.New("invalid")
	ErrFailed  = errors.New("internal error")
)

type Service struct {
	cfg    config.Config
	client *redis.Client
}

func New(
	cfg config.Config,
	client *redis.Client,
) Service {
	return Service{
		cfg:    cfg,
		client: client,
	}
}

type otp struct {
	Code      string
	Hash      string
	ExpiresAt time.Time
	Error     *error
}

func (s Service) Generate(ctx context.Context, payload map[string]any) otp {
	code, err := generate(s.cfg.GetLength(), s.cfg.GetCharset())
	if err != nil {
		return otp{Error: &err}
	}

	expireAt := time.Now().Local().Add(s.cfg.GetTTL())

	hash, err := build(
		code,
		expireAt.Unix(),
		payload,
		s.cfg.GetSecret(),
		s.cfg.GetAlgorithm(),
	)
	if err != nil {
		return otp{Error: &err}
	}

	s.client.HSet(
		ctx,
		s.prefix(hash),
		map[string]any{
			"code":    code,
			"exp":     expireAt.Unix(),
			"payload": payload,
		},
	)
	s.client.Expire(ctx, s.prefix(hash), s.cfg.GetTTL())

	return otp{
		Code:      code,
		Hash:      hash,
		ExpiresAt: expireAt,
		Error:     nil,
	}
}

func (s Service) Verify(ctx context.Context, hash string, code string) (map[string]any, error) {
	key := s.prefix(hash)

	const script = `
		local data = redis.call("HMGET", KEYS[1], "code", "payload")

		if not data[1] then
			return {0, nil}
		end

		if data[1] ~= ARGV[1] then
			return {-1, nil}
		end

		local payload = data[2]

		redis.call("DEL", KEYS[1])
		return {1, payload}
	`

	res, err := s.client.Eval(ctx, script, []string{key}, code).Result()
	if err != nil {
		return nil, ErrFailed
	}

	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, ErrFailed
	}

	status := arr[0].(int64)

	switch status {
	case 1:
		// success
		var payload map[string]any

		if arr[1] != nil {
			_ = json.Unmarshal([]byte(arr[1].(string)), &payload)
		}

		return payload, nil

	case 0:
		return nil, ErrExpired

	case -1:
		return nil, ErrInvalid

	default:
		return nil, ErrInvalid
	}
}

func (s Service) prefix(val string) string {
	v := s.cfg.GetPrefix()
	fmt.Println(v)
	return fmt.Sprintf("%s:%s", s.cfg.GetCharset(), val)
}
