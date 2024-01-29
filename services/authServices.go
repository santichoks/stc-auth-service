package services

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/pkgs/jwtAuth"
	"github.com/santichoks/stc-auth-service/repositories"
)

type AuthService interface {
	SignUpSrv(req models.SignUpReq, cfg *config.Config)
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

func (srv authService) SignUpSrv(req models.SignUpReq, cfg *config.Config) {
	myClaims := jwtAuth.MyClaims{
		UserId:    "",
		Email:     "myemail@stc.com",
		FirstName: "Santichok",
		LastName:  "Sangarun",
	}

	tokenString := jwtAuth.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims).SignToken()
	fmt.Println(tokenString)

	token, _ := jwt.ParseWithClaims(tokenString, &jwtAuth.ClaimsWithOriginal{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(cfg.Jwt.AccessTokenSecret), nil
	})

	if v, ok := token.Claims.(*jwtAuth.ClaimsWithOriginal); ok {
		fmt.Println(v)
	}
}
