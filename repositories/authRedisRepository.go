package repositories

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type AuthRedisRepository interface {
}

type authRedisRepository struct {
	redis *redis.Client
}

func NewAuthRedisRepository(redisClient *redis.Client) AuthRedisRepository {
	return authRedisRepository{
		redis: redisClient,
	}
}

func (r authRedisRepository) Get(key string) (string, error) {
	value, err := r.redis.Get(context.Background(), key).Result()
	if err != nil {
		return "", err
	}

	return value, nil
}

func (r authRedisRepository) Set(key string, value string, exp time.Duration) error {
	err := r.redis.Set(context.Background(), key, value, exp).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r authRedisRepository) Delete(key []string) (int64, error) {
	count, err := r.redis.Del(context.Background(), key...).Result()
	if err != nil {
		return 0, err
	}

	return count, nil
}
