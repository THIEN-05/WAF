package redis

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func Open(ctx context.Context, addr, password string, db int) (*redis.Client, error) {
	c := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db, PoolSize: 64, MinIdleConns: 4})
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
