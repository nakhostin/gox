package session

import "time"

type Option func(*Service)

func WithNowFunc(fn func() time.Time) Option {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

func WithIDGenerator(fn func() string) Option {
	return func(s *Service) {
		if fn != nil {
			s.idGenerator = fn
		}
	}
}

func WithRefreshTokenGenerator(fn func(int) (string, error)) Option {
	return func(s *Service) {
		if fn != nil {
			s.refreshTokenGenerator = fn
		}
	}
}
