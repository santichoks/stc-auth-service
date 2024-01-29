package repositories

import (
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthMongoRepository interface {
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
	return r.mongodb.Database(collectionName).Collection(collectionName)
}
