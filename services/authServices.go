package services

import (
	"errors"
	"time"

	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/pkgs/jwtPkg"
	"github.com/santichoks/stc-auth-service/repositories"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	LoginSrv(req models.LoginReq, cfg *config.Config) (*models.TokenRes, error)
	LogoutSrv(accessToken string, refreshToken string, cfg *config.Config) error
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

	myClaims := jwtPkg.MyClaims{
		UserId:    user.Id.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	accessToken := jwtPkg.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims)
	refreshToken := jwtPkg.InitRefreshToken(cfg.Jwt.RefreshTokenSecret, cfg.Jwt.RefreshTokenDuration, &myClaims)
	tokenRes := models.TokenRes{
		AccessToken:  accessToken.SignToken(),
		RefreshToken: refreshToken.SignToken(),
	}

	return &tokenRes, nil
}

func (srv authService) LogoutSrv(accessToken, refreshToken string, cfg *config.Config) error {
	accesTtokenClaims, err := jwtPkg.ParseToken(accessToken, cfg.Jwt.AccessTokenSecret)
	refreshTokenClaims, err := jwtPkg.ParseToken(refreshToken, cfg.Jwt.RefreshTokenSecret)

	accessTokenExpiredAt := accesTtokenClaims.ExpiresAt.Time.Sub(time.Now())
	refreshTokenExpiredAt := refreshTokenClaims.ExpiresAt.Time.Sub(time.Now())

	err = srv.redisRepo.Set(accessToken, "accessToken", accessTokenExpiredAt)
	if err != nil {
		return err
	}

	err = srv.redisRepo.Set(refreshToken, "refreshToken", refreshTokenExpiredAt)
	if err != nil {
		return err
	}

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

	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	objectID, err := srv.mongoRepo.InsertOneUser(user)
	if err != nil {
		return nil, err
	}

	myClaims := jwtPkg.MyClaims{
		UserId:    objectID.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	accessToken := jwtPkg.InitAccessToken(cfg.Jwt.AccessTokenSecret, cfg.Jwt.AccessTokenDuration, &myClaims)
	refreshToken := jwtPkg.InitRefreshToken(cfg.Jwt.RefreshTokenSecret, cfg.Jwt.RefreshTokenDuration, &myClaims)
	tokenRes := models.TokenRes{
		AccessToken:  accessToken.SignToken(),
		RefreshToken: refreshToken.SignToken(),
	}

	return &tokenRes, nil
}
