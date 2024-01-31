package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AllowOrigins  string
	AllowHeaders  string
	MongoHost     string
	MongoUsername string
	MongoPassword string
	RedisHost     string
	RedisPassword string
	KafkaHost     string
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
		AllowHeaders:  os.Getenv("ACCESS_HEADERS"),
		MongoHost:     os.Getenv("MONGO_HOST"),
		MongoUsername: os.Getenv("MONGO_USERNAME"),
		MongoPassword: os.Getenv("MONGO_PASSWORD"),
		RedisHost:     os.Getenv("REDIS_HOST"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		KafkaHost:     os.Getenv("KAFKA_HOST"),
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
