package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AllowOrigins  string
	MongoUri      string
	RedisUri      string
	RedisPassword string
	KafkaUri      string
	Jwt           Jwt
}

type Jwt struct {
	AccessTokenSecret    string
	AccessTokenDuration  int64
	RefreshTokenSecret   string
	RefreshTokenDuration int64
}

func GetConfig() Config {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error Loading .env File : %s", err.Error())
	}

	return Config{
		AllowOrigins:  os.Getenv("ACCESS_ORIGINS"),
		MongoUri:      os.Getenv("MONGO_URI"),
		RedisUri:      os.Getenv("REDIS_URI"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		KafkaUri:      os.Getenv("KAFKA_URI"),
		Jwt: Jwt{
			AccessTokenSecret: os.Getenv("JWT_ACCESS_TOKEN_SECRET"),
			AccessTokenDuration: func() int64 {
				res, err := strconv.ParseInt(os.Getenv("JWT_ACCESS_TOKEN_DURATION"), 10, 64)
				if err != nil {
					log.Fatalf("Error loading JWT_ACCESS_DURATION : %s", err.Error())
				}

				return res
			}(),
			RefreshTokenSecret: os.Getenv("JWT_REFRESH_TOKEN_SECRET"),
			RefreshTokenDuration: func() int64 {
				res, err := strconv.ParseInt(os.Getenv("JWT_REFRESH_TOKEN_DURATION"), 10, 64)
				if err != nil {
					log.Fatalf("Error loading JWT_REFRESH_DURATION : %s", err.Error())
				}

				return res
			}(),
		},
	}
}
