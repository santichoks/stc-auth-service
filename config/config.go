package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AllowOrigins   string
	App            App
	MongoUri       string
	RedisUri       string
	RedisPassword  string
	GrpcUri        string
	KafkaUri       string
	KafkaApiKey    string
	KafkaSecretKey string
	Jwt            Jwt
}

type App struct {
	Name  string
	Url   string
	Stage string
}

type Jwt struct {
	AccessSecretKey  string
	RefreshSecretKey string
	ApiSecretKey     string
	AccessDuration   int64
	RefreshDuration  int64
}

func GetConfig() Config {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error Loading .env File : %s", err.Error())
	}

	return Config{
		AllowOrigins: os.Getenv("ACCESS_ORIGINS"),
		App: App{
			Name:  os.Getenv("APP_NAME"),
			Url:   os.Getenv("APP_URL"),
			Stage: os.Getenv("APP_STAGE"),
		},
		MongoUri:       os.Getenv("MONGO_URI"),
		RedisUri:       os.Getenv("REDIS_URI"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		GrpcUri:        os.Getenv("GRPC_URI"),
		KafkaUri:       os.Getenv("KAFKA_URI"),
		KafkaApiKey:    os.Getenv("KAFKA_API_KEY"),
		KafkaSecretKey: os.Getenv("KAFKA_SECRET_KEY"),
		Jwt: Jwt{
			AccessSecretKey:  os.Getenv("JWT_ACCESS_SECRET_KEY"),
			RefreshSecretKey: os.Getenv("JWT_REFRESH_SECRET_KEY"),
			ApiSecretKey:     os.Getenv("JWT_API_SECRET_KEY"),
			AccessDuration: func() int64 {
				res, err := strconv.ParseInt(os.Getenv("JWT_ACCESS_DURATION"), 10, 64)
				if err != nil {
					log.Fatalf("Error loading JWT_ACCESS_DURATION : %s", err.Error())
				}

				return res
			}(),
			RefreshDuration: func() int64 {
				res, err := strconv.ParseInt(os.Getenv("JWT_REFRESH_DURATION"), 10, 64)
				if err != nil {
					log.Fatalf("Error loading JWT_REFRESH_DURATION : %s", err.Error())
				}

				return res
			}(),
		},
	}
}
