package config

import (
	"time"

	"github.com/nakhostin/gox/otp/algorithm"
)

type Config struct {
	length    int
	ttl       time.Duration
	algorithm algorithm.Algorithm
	secret    string
	charset   string
	prefix    string
}

func New() *Config {
	return &Config{
		length:    6,
		ttl:       time.Minute * 2,
		algorithm: algorithm.AlgorithmHMACSHA256,
		secret:    "gox-secret",
		charset:   Digits,
		prefix:    "gox",
	}
}

func (c *Config) WithLength(length int) *Config {
	c.length = length
	return c
}

func (c *Config) WithTTL(ttl time.Duration) *Config {
	c.ttl = ttl
	return c
}

func (c *Config) WithAlgorithm(algorithm algorithm.Algorithm) *Config {
	c.algorithm = algorithm
	return c
}

func (c *Config) WithSecret(secret string) *Config {
	c.secret = secret
	return c
}

func (c *Config) WithCharset(charset string) *Config {
	c.charset = charset
	return c
}

func (c *Config) WithPrefix(prefix string) *Config {
	c.prefix = prefix
	return c
}

func (c *Config) Build() Config {
	return *c
}

func (c *Config) GetLength() int {
	return c.length
}

func (c *Config) GetTTL() time.Duration {
	return c.ttl
}

func (c *Config) GetAlgorithm() algorithm.Algorithm {
	return c.algorithm
}

func (c *Config) GetSecret() string {
	return c.secret
}

func (c *Config) GetCharset() string {
	return c.charset
}

func (c *Config) GetPrefix() string {
	return c.prefix
}
