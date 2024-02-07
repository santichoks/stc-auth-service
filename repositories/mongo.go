package repositories

import (
	"context"
	"errors"
	"time"

	"github.com/santichoks/stc-auth-service/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthMongoRepository interface {
	FindOneUserByEmail(email string) (*models.User, error)
	InsertOneUser(user models.User) (primitive.ObjectID, error)
	UpdateOneUserPasswordByEmail(email string, hashedNewPassword string) error
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

func (r authMongoRepository) UpdateOneUserPasswordByEmail(email string, hashedNewPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "password", Value: hashedNewPassword}}}}

	result, err := r.OpenCollection("users").UpdateOne(ctx, bson.D{{Key: "email", Value: email}}, update)
	if err != nil {
		return err
	}

	if result.ModifiedCount != 1 {
		return errors.New("document not found or not updated")
	}

	return nil
}
