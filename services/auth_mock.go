package services

import (
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/stretchr/testify/mock"
)

type authServiceMock struct {
	mock.Mock
}

func NewAuthServiceMock() *authServiceMock {
	return &authServiceMock{}
}

func (m *authServiceMock) LoginSrv(req models.LoginReq, cfg *config.Config) (*models.TokenRes, error) {
	args := m.Called(req, cfg)

	return args.Get(0).(*models.TokenRes), args.Error(1)
}

func (m *authServiceMock) LogoutSrv(accessToken, refreshToken string, cfg *config.Config) error {
	args := m.Called(accessToken, refreshToken, cfg)

	return args.Error(0)
}

func (m *authServiceMock) SignupSrv(req models.SignupReq, cfg *config.Config) (*models.TokenRes, error) {
	args := m.Called(req, cfg)

	return args.Get(0).(*models.TokenRes), args.Error(1)
}
