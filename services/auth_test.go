package services_test

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/pkgs/jwtPkg"
	"github.com/santichoks/stc-auth-service/repositories"
	"github.com/santichoks/stc-auth-service/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginSrv(t *testing.T) {
	type testCase struct {
		Name                 string
		ID                   primitive.ObjectID
		FirstName            string
		LastName             string
		Email                string
		Password             string
		CreatedAt            time.Time
		UpdatedAt            time.Time
		AccessTokenSecret    string
		AccessTokenDuration  int64
		RefreshTokenSecret   string
		RefreshTokenDuration int64
		HashedPassword       string
	}

	mockHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.DefaultCost)
	cases := []testCase{
		{
			Name:                 "LoginSrv Successful",
			ID:                   primitive.NewObjectID(),
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "santichok@stc.com",
			Password:             "123456",
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
			HashedPassword:       string(mockHashedPassword),
		},
		{
			Name:                 "LoginSrv Invalid Email",
			ID:                   primitive.NewObjectID(),
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "fake@stc.com",
			Password:             "123456",
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
			HashedPassword:       string(mockHashedPassword),
		},
		{
			Name:                 "LoginSrv Invalid Password",
			ID:                   primitive.NewObjectID(),
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "fake@stc.com",
			Password:             "000000",
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
			HashedPassword:       string(mockHashedPassword),
		},
	}

	t.Run(cases[0].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[0].Email).Return(&models.User{
			Id:        cases[0].ID,
			FirstName: cases[0].FirstName,
			LastName:  cases[0].LastName,
			Email:     cases[0].Email,
			Password:  cases[0].HashedPassword,
			CreatedAt: cases[0].CreatedAt,
			UpdatedAt: cases[0].UpdatedAt,
		}, nil)

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		loginReq := models.LoginReq{
			Email:    cases[0].Email,
			Password: cases[0].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[0].AccessTokenSecret,
				AccessTokenDuration:  cases[0].AccessTokenDuration,
				RefreshTokenSecret:   cases[0].RefreshTokenSecret,
				RefreshTokenDuration: cases[0].RefreshTokenDuration,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		resultToken, _ := authSrv.LoginSrv(loginReq, &config)

		expectMyClaims := jwtPkg.MyClaims{
			UserId:    cases[0].ID.String(),
			Email:     cases[0].Email,
			FirstName: cases[0].FirstName,
			LastName:  cases[0].LastName,
		}

		expectAccessToken := jwtPkg.InitAccessToken(cases[0].AccessTokenSecret, int64(cases[0].AccessTokenDuration), &expectMyClaims).SignToken()
		expectRefreshToken := jwtPkg.InitRefreshToken(cases[0].RefreshTokenSecret, int64(cases[0].RefreshTokenDuration), &expectMyClaims).SignToken()
		expectToken := models.TokenRes{
			AccessToken:  expectAccessToken,
			RefreshToken: expectRefreshToken,
		}

		assert.Equal(t, expectToken.AccessToken, resultToken.AccessToken)
	})

	t.Run(cases[1].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[1].Email).Return(&models.User{
			Id:        cases[1].ID,
			FirstName: cases[1].FirstName,
			LastName:  cases[1].LastName,
			Email:     cases[1].Email,
			Password:  cases[1].HashedPassword,
			CreatedAt: cases[1].CreatedAt,
			UpdatedAt: cases[1].UpdatedAt,
		}, errors.New(""))

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		loginReq := models.LoginReq{
			Email:    cases[1].Email,
			Password: cases[1].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[1].AccessTokenSecret,
				AccessTokenDuration:  cases[1].AccessTokenDuration,
				RefreshTokenSecret:   cases[1].RefreshTokenSecret,
				RefreshTokenDuration: cases[1].RefreshTokenDuration,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		_, err := authSrv.LoginSrv(loginReq, &config)

		assert.Error(t, err)
	})

	t.Run(cases[2].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[2].Email).Return(&models.User{
			Id:        cases[2].ID,
			FirstName: cases[2].FirstName,
			LastName:  cases[2].LastName,
			Email:     cases[2].Email,
			Password:  cases[2].HashedPassword,
			CreatedAt: cases[2].CreatedAt,
			UpdatedAt: cases[2].UpdatedAt,
		}, nil)

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		loginReq := models.LoginReq{
			Email:    cases[2].Email,
			Password: cases[2].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[2].AccessTokenSecret,
				AccessTokenDuration:  cases[2].AccessTokenDuration,
				RefreshTokenSecret:   cases[2].RefreshTokenSecret,
				RefreshTokenDuration: cases[2].RefreshTokenDuration,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		_, err := authSrv.LoginSrv(loginReq, &config)

		assert.Error(t, err)
	})
}

func TestLogoutSrv(t *testing.T) {
	type testCase struct {
		Name               string
		AccessToken        string
		AccessTokenSecret  string
		RefreshToken       string
		RefreshTokenSecret string
	}

	mockID := primitive.NewObjectID()
	mockEmail := "santichok@stc.com"
	mockFirstName := "santichok"
	mockLastName := "sangarun"
	mockAccessTokenSecret := "mock-access-token-secret"
	mockRefreshTokenSecret := "mock-refresh-token-secret"

	myClaims := jwtPkg.MyClaims{
		UserId:    mockID.String(),
		Email:     mockEmail,
		FirstName: mockFirstName,
		LastName:  mockLastName,
	}

	accessToken := jwtPkg.InitAccessToken(mockAccessTokenSecret, 86400, &myClaims).SignToken()
	refreshToken := jwtPkg.InitRefreshToken(mockRefreshTokenSecret, 86400, &myClaims).SignToken()

	cases := []testCase{
		{
			Name:               "LogoutSrv Successful",
			AccessToken:        accessToken,
			AccessTokenSecret:  mockAccessTokenSecret,
			RefreshToken:       refreshToken,
			RefreshTokenSecret: mockRefreshTokenSecret,
		},
		{
			Name:               "LogoutSrv Invalid Access Token",
			AccessToken:        "invalid_access_token",
			AccessTokenSecret:  mockAccessTokenSecret,
			RefreshToken:       refreshToken,
			RefreshTokenSecret: mockRefreshTokenSecret,
		},
		{
			Name:               "LogoutSrv Invalid Refresh Token",
			AccessToken:        accessToken,
			AccessTokenSecret:  mockAccessTokenSecret,
			RefreshToken:       "invalid_refresh_token",
			RefreshTokenSecret: mockRefreshTokenSecret,
		},
		{
			Name:               "LogoutSrv Set Access Token To Black List Fail",
			AccessToken:        accessToken,
			AccessTokenSecret:  mockAccessTokenSecret,
			RefreshToken:       refreshToken,
			RefreshTokenSecret: mockRefreshTokenSecret,
		},
		{
			Name:               "LogoutSrv Set Refresh Token To Black List Fail",
			AccessToken:        accessToken,
			AccessTokenSecret:  mockAccessTokenSecret,
			RefreshToken:       refreshToken,
			RefreshTokenSecret: mockRefreshTokenSecret,
		},
	}

	t.Run(cases[0].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authRedisRepo.On("Set", accessToken, "accessToken", mock.AnythingOfType("time.Duration")).Return(nil)
		authRedisRepo.On("Set", refreshToken, "refreshToken", mock.AnythingOfType("time.Duration")).Return(nil)

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:  cases[0].AccessTokenSecret,
				RefreshTokenSecret: cases[0].RefreshTokenSecret,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.LogoutSrv(cases[0].AccessToken, cases[0].RefreshToken, &config)

		assert.Equal(t, nil, err)
	})

	t.Run(cases[1].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:  cases[1].AccessTokenSecret,
				RefreshTokenSecret: cases[1].RefreshTokenSecret,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.LogoutSrv(cases[1].AccessToken, cases[1].RefreshToken, &config)

		assert.Error(t, err)
	})

	t.Run(cases[2].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:  cases[2].AccessTokenSecret,
				RefreshTokenSecret: cases[2].RefreshTokenSecret,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.LogoutSrv(cases[2].AccessToken, cases[2].RefreshToken, &config)

		assert.Error(t, err)
	})

	t.Run(cases[3].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authRedisRepo.On("Set", accessToken, "accessToken", mock.AnythingOfType("time.Duration")).Return(errors.New(""))

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:  cases[3].AccessTokenSecret,
				RefreshTokenSecret: cases[3].RefreshTokenSecret,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.LogoutSrv(cases[3].AccessToken, cases[3].RefreshToken, &config)

		assert.Error(t, err)
	})

	t.Run(cases[4].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authRedisRepo.On("Set", accessToken, "accessToken", mock.AnythingOfType("time.Duration")).Return(nil)
		authRedisRepo.On("Set", refreshToken, "refreshToken", mock.AnythingOfType("time.Duration")).Return(errors.New(""))

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:  cases[4].AccessTokenSecret,
				RefreshTokenSecret: cases[4].RefreshTokenSecret,
			},
		}

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.LogoutSrv(cases[4].AccessToken, cases[4].RefreshToken, &config)

		assert.Error(t, err)
	})
}

func TestSignupSrv(t *testing.T) {
	type testCase struct {
		Name                 string
		FirstName            string
		LastName             string
		Email                string
		Password             string
		AccessTokenSecret    string
		AccessTokenDuration  int64
		RefreshTokenSecret   string
		RefreshTokenDuration int64
	}

	cases := []testCase{
		{
			Name:                 "SignupSrv Successful",
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "santichok@stc.com",
			Password:             "123456",
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
		},
		{
			Name:                 "SignupSrv Successful",
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "santichok@stc.com",
			Password:             "123456",
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
		},
		{
			Name:                 "SignupSrv Successful",
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "santichok@stc.com",
			Password:             "123456",
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
		},
		{
			Name:                 "SignupSrv Successful",
			FirstName:            "santichok",
			LastName:             "sangarun",
			Email:                "santichok@stc.com",
			Password:             "123456",
			AccessTokenSecret:    "mock-access-token-secret",
			AccessTokenDuration:  86400,
			RefreshTokenSecret:   "mock-refresh-token-secret",
			RefreshTokenDuration: 86400,
		},
	}

	t.Run(cases[0].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[0].Email).Return(&models.User{}, mongo.ErrNoDocuments)
		authMongoRepo.On("InsertOneUser", mock.Anything).Return(primitive.NewObjectID(), nil)

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)

		req := models.SignupReq{
			FirstName: cases[0].FirstName,
			LastName:  cases[0].LastName,
			Email:     cases[0].Email,
			Password:  cases[0].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[0].AccessTokenSecret,
				AccessTokenDuration:  cases[0].AccessTokenDuration,
				RefreshTokenSecret:   cases[0].RefreshTokenSecret,
				RefreshTokenDuration: cases[0].RefreshTokenDuration,
			},
		}

		tokenRes, _ := authSrv.SignupSrv(req, &config)

		assert.Equal(t, reflect.TypeOf(&models.TokenRes{}).String(), reflect.TypeOf(tokenRes).String())
	})

	t.Run(cases[1].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[0].Email).Return(&models.User{}, errors.New(""))

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)

		req := models.SignupReq{
			FirstName: cases[1].FirstName,
			LastName:  cases[1].LastName,
			Email:     cases[1].Email,
			Password:  cases[1].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[1].AccessTokenSecret,
				AccessTokenDuration:  cases[1].AccessTokenDuration,
				RefreshTokenSecret:   cases[1].RefreshTokenSecret,
				RefreshTokenDuration: cases[1].RefreshTokenDuration,
			},
		}

		_, err := authSrv.SignupSrv(req, &config)

		assert.Error(t, err)
	})

	t.Run(cases[2].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[0].Email).Return(&models.User{}, nil)

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)

		req := models.SignupReq{
			FirstName: cases[2].FirstName,
			LastName:  cases[2].LastName,
			Email:     cases[2].Email,
			Password:  cases[2].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[2].AccessTokenSecret,
				AccessTokenDuration:  cases[2].AccessTokenDuration,
				RefreshTokenSecret:   cases[2].RefreshTokenSecret,
				RefreshTokenDuration: cases[2].RefreshTokenDuration,
			},
		}

		_, err := authSrv.SignupSrv(req, &config)

		assert.Error(t, err)
	})

	t.Run(cases[3].Name, func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", cases[0].Email).Return(&models.User{}, mongo.ErrNoDocuments)
		authMongoRepo.On("InsertOneUser", mock.Anything).Return(primitive.NewObjectID(), errors.New(""))

		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)

		req := models.SignupReq{
			FirstName: cases[3].FirstName,
			LastName:  cases[3].LastName,
			Email:     cases[3].Email,
			Password:  cases[3].Password,
		}

		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret:    cases[3].AccessTokenSecret,
				AccessTokenDuration:  cases[3].AccessTokenDuration,
				RefreshTokenSecret:   cases[3].RefreshTokenSecret,
				RefreshTokenDuration: cases[3].RefreshTokenDuration,
			},
		}

		_, err := authSrv.SignupSrv(req, &config)

		assert.Error(t, err)
	})
}

func TestResetPasswordSrv(t *testing.T) {
	t.Run("ResetPasswordSrv Successful", func(t *testing.T) {
		godotenv.Load("../.env")
		config := config.Config{
			SmtpHost:                   os.Getenv("SMTP_HOST"),
			SmtpPort:                   os.Getenv("SMTP_PORT"),
			SenderEmail:                os.Getenv("SENDER_EMAIL"),
			SenderPassword:             os.Getenv("SENDER_PASSWORD"),
			ResetPasswordTokenDuration: 900,
		}

		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{}, nil)
		authRedisRepo.On("Set", mock.AnythingOfType("string"), "santichok@stc.com", time.Duration(config.ResetPasswordTokenDuration)*time.Second).Return(nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ResetPasswordSrv(models.ResetPasswordReq{Email: "santichok@stc.com"}, &config)

		assert.Equal(t, nil, err)
	})

	t.Run("ResetPasswordSrv Send Email Failed", func(t *testing.T) {
		config := config.Config{
			ResetPasswordTokenDuration: 900,
		}

		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{}, nil)
		authRedisRepo.On("Set", mock.AnythingOfType("string"), "santichok@stc.com", time.Duration(config.ResetPasswordTokenDuration)*time.Second).Return(nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ResetPasswordSrv(models.ResetPasswordReq{Email: "santichok@stc.com"}, &config)

		assert.Error(t, err)
	})

	t.Run("ResetPasswordSrv Set Redis Failed", func(t *testing.T) {
		config := config.Config{}

		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{}, nil)
		authRedisRepo.On("Set", mock.AnythingOfType("string"), "santichok@stc.com", time.Duration(config.ResetPasswordTokenDuration)*time.Second).Return(errors.New(""))

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ResetPasswordSrv(models.ResetPasswordReq{Email: "santichok@stc.com"}, &config)

		assert.Error(t, err)
	})

	t.Run("ResetPasswordSrv Invalid Email", func(t *testing.T) {
		config := config.Config{}

		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{}, errors.New(""))
		authRedisRepo.On("Set", mock.AnythingOfType("string"), "santichok@stc.com", time.Duration(config.ResetPasswordTokenDuration)*time.Second).Return(errors.New(""))

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ResetPasswordSrv(models.ResetPasswordReq{Email: "santichok@stc.com"}, &config)

		assert.Error(t, err)
	})
}

func TestChangePasswordSrv(t *testing.T) {
	t.Run("ChangePasswordSrv With Token Successful", func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("UpdateOneUserPasswordByEmail", "santichok@stc.com", mock.AnythingOfType("string")).Return(nil)
		authRedisRepo.On("Get", "mockresetpasswordtoken").Return("santichok@stc.com", nil)

		var deleteCount int64 = 1
		authRedisRepo.On("Delete", []string{"mockresetpasswordtoken"}).Return(deleteCount, nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ChangePasswordSrv(models.ChangePasswordReq{}, "mockresetpasswordtoken", "mockaccesstoken", &config.Config{})

		assert.Equal(t, nil, err)
	})

	t.Run("ChangePasswordSrv With Token Update Failed", func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("UpdateOneUserPasswordByEmail", "santichok@stc.com", mock.AnythingOfType("string")).Return(errors.New(""))
		authRedisRepo.On("Get", "mockresetpasswordtoken").Return("santichok@stc.com", nil)

		var deleteCount int64 = 1
		authRedisRepo.On("Delete", []string{"mockresetpasswordtoken"}).Return(deleteCount, nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ChangePasswordSrv(models.ChangePasswordReq{}, "mockresetpasswordtoken", "mockaccesstoken", &config.Config{})

		assert.Error(t, err)
	})

	t.Run("ChangePasswordSrv With Token Get Redis Failed", func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("UpdateOneUserPasswordByEmail", "santichok@stc.com", mock.AnythingOfType("string")).Return(errors.New(""))
		authRedisRepo.On("Get", "mockresetpasswordtoken").Return("santichok@stc.com", errors.New(""))

		var deleteCount int64 = 1
		authRedisRepo.On("Delete", []string{"mockresetpasswordtoken"}).Return(deleteCount, nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		err := authSrv.ChangePasswordSrv(models.ChangePasswordReq{}, "mockresetpasswordtoken", "mockaccesstoken", &config.Config{})

		assert.Error(t, err)
	})

	t.Run("ChangePasswordSrv With Old Password Successful", func(t *testing.T) {
		token := jwtPkg.InitAccessToken("mocktokensecret", 100, &jwtPkg.MyClaims{Email: "santichok@stc.com"}).SignToken()
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte("mockoldpassword"), bcrypt.DefaultCost)
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{
			Email:    "santichok@stc.com",
			Password: string(hashedOldPassword),
		}, nil)
		authMongoRepo.On("UpdateOneUserPasswordByEmail", "santichok@stc.com", mock.AnythingOfType("string")).Return(nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret: "mocktokensecret",
			},
		}

		req := models.ChangePasswordReq{
			OldPassword: "mockoldpassword",
			NewPassword: "mocknewpassword",
		}
		err := authSrv.ChangePasswordSrv(req, "", token, &config)

		assert.Equal(t, nil, err)
	})

	t.Run("ChangePasswordSrv With Old Password Update Password Failed", func(t *testing.T) {
		token := jwtPkg.InitAccessToken("mocktokensecret", 100, &jwtPkg.MyClaims{Email: "santichok@stc.com"}).SignToken()
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte("mockoldpassword"), bcrypt.DefaultCost)
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{
			Email:    "santichok@stc.com",
			Password: string(hashedOldPassword),
		}, nil)
		authMongoRepo.On("UpdateOneUserPasswordByEmail", "santichok@stc.com", mock.AnythingOfType("string")).Return(errors.New(""))

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret: "mocktokensecret",
			},
		}

		req := models.ChangePasswordReq{
			OldPassword: "mockoldpassword",
			NewPassword: "mocknewpassword",
		}
		err := authSrv.ChangePasswordSrv(req, "", token, &config)

		assert.Error(t, err)
	})

	t.Run("ChangePasswordSrv With Old Password Invalid Old Password", func(t *testing.T) {
		token := jwtPkg.InitAccessToken("mocktokensecret", 100, &jwtPkg.MyClaims{Email: "santichok@stc.com"}).SignToken()
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte("mockoldpassword"), bcrypt.DefaultCost)
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{
			Email:    "santichok@stc.com",
			Password: string(hashedOldPassword),
		}, nil)

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret: "mocktokensecret",
			},
		}

		req := models.ChangePasswordReq{
			OldPassword: "xxxxxxxxxxxxxxx",
			NewPassword: "mocknewpassword",
		}
		err := authSrv.ChangePasswordSrv(req, "", token, &config)

		assert.Error(t, err)
	})

	t.Run("ChangePasswordSrv With Old Password No Document", func(t *testing.T) {
		token := jwtPkg.InitAccessToken("mocktokensecret", 100, &jwtPkg.MyClaims{Email: "santichok@stc.com"}).SignToken()
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()
		authMongoRepo.On("FindOneUserByEmail", "santichok@stc.com").Return(&models.User{}, errors.New(""))

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret: "mocktokensecret",
			},
		}

		req := models.ChangePasswordReq{
			OldPassword: "xxxxxxxxxxxxxxx",
			NewPassword: "mocknewpassword",
		}
		err := authSrv.ChangePasswordSrv(req, "", token, &config)

		assert.Error(t, err)
	})

	t.Run("ChangePasswordSrv With Old Parse Token Failed", func(t *testing.T) {
		authMongoRepo := repositories.NewAuthMongoRepositoryMock()
		authRedisRepo := repositories.NewAuthRedisRepositoryMock()

		authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
		config := config.Config{
			Jwt: config.Jwt{
				AccessTokenSecret: "mocktokensecret",
			},
		}

		req := models.ChangePasswordReq{
			OldPassword: "xxxxxxxxxxxxxxx",
			NewPassword: "mocknewpassword",
		}
		err := authSrv.ChangePasswordSrv(req, "", "xxxxx", &config)

		assert.Error(t, err)
	})
}
