package databases

import (
	"github.com/redis/go-redis/v9"
	"github.com/santichoks/stc-auth-service/config"
)

func NewRedisConnection(cfg *config.Config) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisUri,
		Password: cfg.RedisPassword,
		DB:       1,
	})

	return client
}
