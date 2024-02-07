package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
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
	ResetPasswordSrv(req models.ResetPasswordReq, cfg *config.Config) error
	ChangePasswordSrv(req models.ChangePasswordReq, resetPasswordToken string, accessToken string, cfg *config.Config) error
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
	accessTokenClaims, err := jwtPkg.ParseToken(accessToken, cfg.Jwt.AccessTokenSecret)
	if err != nil {
		return err
	}

	refreshTokenClaims, err := jwtPkg.ParseToken(refreshToken, cfg.Jwt.RefreshTokenSecret)
	if err != nil {
		return err
	}

	accessTokenExpiredAt := accessTokenClaims.ExpiresAt.Time.Sub(time.Now())
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
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}
	if err == nil {
		return nil, errors.New("email already exists")
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	user := models.User{
		FirstName: strings.ToLower(req.FirstName),
		LastName:  strings.ToLower(req.LastName),
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

func (srv authService) ResetPasswordSrv(req models.ResetPasswordReq, cfg *config.Config) error {
	_, err := srv.mongoRepo.FindOneUserByEmail(req.Email)
	if err != nil {
		return errors.New("invalid email")
	}

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	err = srv.redisRepo.Set(token, req.Email, time.Duration(cfg.ResetPasswordTokenDuration)*time.Second)
	if err != nil {
		return err
	}

	body := fmt.Sprintf(
		`<html>
			<head>
				<style>
					body {
						font-family: Arial, sans-serif;
						background-color: #f4f4f4;
						margin: 0;
						padding: 0;
					}
					.container {
						width: 100vw;
						max-width: 600px;
						margin: 0 auto;
						padding: 20px;
						text-align: center;
						background-color: #ffffff;
						border-radius: 10px;
						box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
					}
					.header {
						color: #333333;
						font-size: 24px;
						margin-bottom: 20px;
					}
					.button {
						display: inline-block;
						padding: 10px 20px;
						background-color: #4CAF50;
						color: white;
						text-align: center;
						text-decoration: none;
						border-radius: 10px;
						cursor: pointer;
						transition: background-color 0.3s ease;
					}
					.button:hover {
						background-color: #45a049;
					}
					.button:visited {
						color: white;
					}
				</style>
			</head>
			<body>
				<div class="container">
					<p class="header">Forgot Your Password?</p>
					<a href="%s/reset-password?token=%s" class="button">Reset Password</a>
					<p>Didn’t request a password reset? You can ignore this message.</p>
				</div>
			</body>
		</html>`, cfg.AllowOrigins, token)

	message := "From: " + cfg.SenderEmail + "\n" +
		"To: " + req.Email + "\n" +
		"Subject: " + "request to reset your password\n" +
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n" +
		body

	auth := smtp.PlainAuth("", cfg.SenderEmail, cfg.SenderPassword, cfg.SmtpHost)
	err = smtp.SendMail(fmt.Sprintf("%s:%s", cfg.SmtpHost, cfg.SmtpPort), auth, cfg.SenderEmail, []string{req.Email}, []byte(message))
	if err != nil {
		return err
	}

	return nil
}

func (srv authService) ChangePasswordSrv(req models.ChangePasswordReq, resetPasswordToken string, accessToken string, cfg *config.Config) error {
	if resetPasswordToken != "" {
		email, err := srv.redisRepo.Get(resetPasswordToken)
		if err != nil {
			return errors.New("invalid reset password token")
		}

		hashedNewPassword, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)

		err = srv.mongoRepo.UpdateOneUserPasswordByEmail(email, string(hashedNewPassword))
		if err != nil {
			return err
		}

		srv.redisRepo.Delete([]string{resetPasswordToken})
	} else {
		accessTokenClaims, err := jwtPkg.ParseToken(accessToken, cfg.Jwt.AccessTokenSecret)
		if err != nil {
			return err
		}

		user, err := srv.mongoRepo.FindOneUserByEmail(accessTokenClaims.Email)
		if err != nil {
			return err
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword))
		if err != nil {
			return errors.New("invalid old password")
		}

		hashedNewPassword, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)

		err = srv.mongoRepo.UpdateOneUserPasswordByEmail(user.Email, string(hashedNewPassword))
		if err != nil {
			return err
		}
	}

	return nil
}
