// Package cache provides the interfaces.Cache implementations. Redis is
// optional; when it is not configured or unavailable, callers fall back to
// direct reads (Phase 4 adds an in-memory LRU).
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements interfaces.Cache on top of a Redis client.
type Redis struct {
	Client *redis.Client
	Prefix string
}

// OpenRedis parses url and creates a client. Connection is lazy.
func OpenRedis(url string) (*Redis, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL")
	}
	return &Redis{Client: redis.NewClient(opts), Prefix: "txshield:"}, nil
}

// Get returns (value, true, nil) on hit and (nil, false, nil) on miss.
func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	b, err := r.Client.Get(ctx, r.Prefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Set stores val with ttl (0 = no expiry).
func (r *Redis) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return r.Client.Set(ctx, r.Prefix+key, val, ttl).Err()
}

// Close releases the client.
func (r *Redis) Close() error { return r.Client.Close() }

// RedisHealth checks Redis reachability. Non-critical: the cache is an
// optimization, so its failure degrades but does not break the service.
type RedisHealth struct{ R *Redis }

func (RedisHealth) Name() string                      { return "redis" }
func (RedisHealth) Critical() bool                    { return false }
func (h RedisHealth) Check(ctx context.Context) error { return h.R.Client.Ping(ctx).Err() }
