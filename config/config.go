package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AllowOrigins               string
	ServiceLists               []Service
	MongoHost                  string
	MongoUsername              string
	MongoPassword              string
	RedisHost                  string
	RedisPassword              string
	SmtpHost                   string
	SmtpPort                   string
	SenderEmail                string
	SenderPassword             string
	ResetPasswordTokenDuration int64
	Jwt                        Jwt
}

type Service struct {
	Host  string `json:"host"`
	Alias string `json:"alias"`
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
		AllowOrigins: os.Getenv("ACCESS_ORIGINS"),
		ServiceLists: func() []Service {
			serviceLists := os.Getenv("SERVICE_LISTS")
			var res []Service
			err := json.Unmarshal([]byte(serviceLists), &res)
			if err != nil {
				log.Fatalf("Error loading SERVICE_LISTS : %s", err.Error())
			}

			return res
		}(),
		MongoHost:      os.Getenv("MONGO_HOST"),
		MongoUsername:  os.Getenv("MONGO_USERNAME"),
		MongoPassword:  os.Getenv("MONGO_PASSWORD"),
		RedisHost:      os.Getenv("REDIS_HOST"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		SmtpHost:       os.Getenv("SMTP_HOST"),
		SmtpPort:       os.Getenv("SMTP_PORT"),
		SenderEmail:    os.Getenv("SENDER_EMAIL"),
		SenderPassword: os.Getenv("SENDER_PASSWORD"),
		ResetPasswordTokenDuration: func() int64 {
			res, err := strconv.ParseInt(os.Getenv("RESET_PASSWORD_TOKEN_DURATION"), 10, 64)
			if err != nil {
				log.Fatalf("Error loading JWT_ACCESS_DURATION : %s", err.Error())
			}

			return res
		}(),
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
