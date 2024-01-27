package services

import "github.com/santichoks/stc-auth-service/repositories"

type AuthService interface {
}

type authService struct {
	mongoRepo repositories.AuthMongoRepository
	redisRepo repositories.AuthRedisRepository
}

func NewAuthService(mongoRepo repositories.AuthMongoRepository, redisRepo repositories.AuthRedisRepository) AuthService {
	return authService{
		mongoRepo: mongoRepo,
		redisRepo: redisRepo,
	}
}
