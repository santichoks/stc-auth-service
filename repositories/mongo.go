package repositories

import (
	"context"
	"time"

	"github.com/santichoks/stc-auth-service/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthMongoRepository interface {
	FindOneUserByEmail(email string) (*models.User, error)
	InsertOneUser(user models.User) (primitive.ObjectID, error)
}

type authMongoRepository struct {
	mongodb *mongo.Client
}

func NewAuthMongoRepository(mongoClient *mongo.Client) AuthMongoRepository {
	return authMongoRepository{
		mongodb: mongoClient,
	}
}

func (r authMongoRepository) OpenCollection(collectionName string) *mongo.Collection {
	return r.mongodb.Database("stc-auth").Collection(collectionName)
}

func (r authMongoRepository) FindOneUserByEmail(email string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	err := r.OpenCollection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r authMongoRepository) InsertOneUser(user models.User) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := r.OpenCollection("users").InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}

	return result.InsertedID.(primitive.ObjectID), nil
}
