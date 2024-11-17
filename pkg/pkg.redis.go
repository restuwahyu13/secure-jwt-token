package pkg

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type (
	Redis interface {
		SetEx(key string, expiration time.Duration, value any) error
		Get(key string) ([]byte, error)
		Del(key string) (int64, error)
		Exists(key string) (int64, error)
		HSet(key string, values ...any) error
		HSetEx(key string, expiration time.Duration, values ...any) error
		HGet(key string, field string) ([]byte, error)
		HExists(key string, field string) (bool, error)
	}

	redis struct {
		redis *goredis.Client
		ctx   context.Context
	}
)

func NewRedis(ctx context.Context, db int, url string) (Redis, error) {
	parseURL, err := goredis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	rdc := goredis.NewClient(&goredis.Options{
		Addr:            parseURL.Addr,
		Password:        parseURL.Password,
		DB:              db,
		MaxRetries:      10,
		PoolSize:        20,
		PoolFIFO:        true,
		ReadTimeout:     time.Duration(time.Second * 30),
		WriteTimeout:    time.Duration(time.Second * 30),
		DialTimeout:     time.Duration(time.Second * 60),
		MinRetryBackoff: time.Duration(time.Second * 60),
		MaxRetryBackoff: time.Duration(time.Second * 120),
	})

	return &redis{redis: rdc, ctx: ctx}, nil
}

func (h *redis) SetEx(key string, expiration time.Duration, value any) error {
	cmd := h.redis.SetEx(h.ctx, key, value, expiration)

	if err := cmd.Err(); err != nil {
		return err
	}

	return nil
}

func (h *redis) Get(key string) ([]byte, error) {
	cmd := h.redis.Get(h.ctx, key)

	if err := cmd.Err(); err != nil {
		return nil, err
	}

	res := cmd.Val()
	return []byte(res), nil
}

func (h *redis) Del(key string) (int64, error) {
	cmd := h.redis.Del(h.ctx, key)

	if err := cmd.Err(); err != nil {
		return 0, err
	}

	return cmd.Val(), nil
}

func (h *redis) Exists(key string) (int64, error) {
	cmd := h.redis.Exists(h.ctx, key)

	if err := cmd.Err(); err != nil {
		return 0, err
	}

	return cmd.Val(), nil
}

func (h *redis) HSet(key string, values ...any) error {
	cmd := h.redis.HSet(h.ctx, key, values...)

	if err := cmd.Err(); err != nil {
		return err
	}

	return nil
}

func (h *redis) HSetEx(key string, expiration time.Duration, values ...any) error {
	cmd := h.redis.HSet(h.ctx, key, values)
	h.redis.Expire(h.ctx, key, expiration)

	if err := cmd.Err(); err != nil {
		return err
	}

	return nil
}

func (h *redis) HGet(key string, field string) ([]byte, error) {
	cmd := h.redis.HGet(h.ctx, key, field)

	if err := cmd.Err(); err != nil {
		return nil, err
	}

	res := cmd.Val()
	return []byte(res), nil
}

func (h *redis) HExists(key string, field string) (bool, error) {
	cmd := h.redis.HExists(h.ctx, key, field)

	if err := cmd.Err(); err != nil {
		return false, err
	}

	res := cmd.Val()
	return res, nil
}
