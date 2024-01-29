package services

import (
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
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
	// myClaims := jwtPackage.MyClaims{
	// 	UserId:    "",
	// 	Email:     "myemail@stc.com",
	// 	FirstName: "Santichok",
	// 	LastName:  "Sangarun",
	// }

	// tokenString := jwtPackage.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims).SignToken()
	// fmt.Println(tokenString)

	// token, _ := jwt.ParseWithClaims(tokenString, &jwtPackage.ClaimsWithOriginal{}, func(t *jwt.Token) (interface{}, error) {
	// 	return []byte(cfg.Jwt.AccessTokenSecret), nil
	// })

	// if v, ok := token.Claims.(*jwtPackage.ClaimsWithOriginal); ok {
	// 	fmt.Println(v)
	// }
}
