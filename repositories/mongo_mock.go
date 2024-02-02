package repositories

import (
	"github.com/santichoks/stc-auth-service/models"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type authMongoRepositoryMock struct {
	mock.Mock
}

func NewAuthMongoRepositoryMock() *authMongoRepositoryMock {
	return &authMongoRepositoryMock{}
}

func (m *authMongoRepositoryMock) FindOneUserByEmail(email string) (*models.User, error) {
	args := m.Called(email)

	return args.Get(0).(*models.User), args.Error(1)
}

func (m *authMongoRepositoryMock) InsertOneUser(user models.User) (primitive.ObjectID, error) {
	args := m.Called(user)

	return args.Get(0).(primitive.ObjectID), args.Error(1)
}
