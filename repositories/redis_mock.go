package repositories

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type authRedisRepositoryMock struct {
	mock.Mock
}

func NewAuthRedisRepositoryMock() *authMongoRepositoryMock {
	return &authMongoRepositoryMock{}
}

func (m *authMongoRepositoryMock) Get(key string) (string, error) {
	args := m.Called(key)

	return args.String(0), args.Error(1)
}

func (m *authMongoRepositoryMock) Set(key string, value string, exp time.Duration) error {
	args := m.Called(key, value, exp)

	return args.Error(0)
}

func (m *authMongoRepositoryMock) Delete(key []string) (int64, error) {
	args := m.Called(key)

	return args.Get(0).(int64), args.Error(1)
}
