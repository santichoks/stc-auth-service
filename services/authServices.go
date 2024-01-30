package services

import (
	"errors"
	"time"

	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	jwt_package "github.com/santichoks/stc-auth-service/pkgs/jwtPackage"
	"github.com/santichoks/stc-auth-service/repositories"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	LoginSrv(req models.LoginReq, cfg *config.Config) (*models.TokenRes, error)
	LogoutSrv(accessToken, refreshToken string) error
	SignupSrv(req models.SignupReq, cfg *config.Config) (*models.TokenRes, error)
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

func (srv authService) LoginSrv(req models.LoginReq, cfg *config.Config) (*models.TokenRes, error) {
	user, err := srv.mongoRepo.FindOneUserByEmail(req.Email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	myClaims := jwt_package.MyClaims{
		UserId:    user.Id.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	accessToken := jwt_package.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims)
	refreshToken := jwt_package.InitRefreshToken(cfg.Jwt.RefreshTokenSecret, cfg.Jwt.RefreshTokenDuration, &myClaims)
	tokenRes := models.TokenRes{
		AccessToken:  accessToken.SignToken(),
		RefreshToken: refreshToken.SignToken(),
	}

	return &tokenRes, nil
}

func (srv authService) LogoutSrv(accessToken, refreshToken string) error {
	var err error
	err = srv.redisRepo.Set(accessToken, "accessToken", 10) // TO-DO ---------------------------------------------
	if err != nil {
		return err
	}

	err = srv.redisRepo.Set(refreshToken, "refreshToken", 10) // TO-DO ---------------------------------------------
	if err != nil {
		return err
	}

	// TO-DO ---------------------------------------------

	// TO-DO ---------------------------------------------

	return nil
}

func (srv authService) SignupSrv(req models.SignupReq, cfg *config.Config) (*models.TokenRes, error) {
	_, err := srv.mongoRepo.FindOneUserByEmail(req.Email)
	if err != nil && err != mongo.ErrNoDocuments {
		return nil, err
	}
	if err == nil {
		return nil, errors.New("email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	location, _ := time.LoadLocation("Asia/Bangkok")
	now := time.Now().In(location)
	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  string(hashedPassword),
		CreatedAt: now,
		UpdatedAt: now,
	}

	objectID, err := srv.mongoRepo.InsertOneUser(user)
	if err != nil {
		return nil, err
	}

	myClaims := jwt_package.MyClaims{
		UserId:    objectID.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	accessToken := jwt_package.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims)
	refreshToken := jwt_package.InitRefreshToken(cfg.Jwt.RefreshTokenSecret, cfg.Jwt.RefreshTokenDuration, &myClaims)
	tokenRes := models.TokenRes{
		AccessToken:  accessToken.SignToken(),
		RefreshToken: refreshToken.SignToken(),
	}

	return &tokenRes, nil
}
