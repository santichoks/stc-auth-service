package databasePkg

import (
	"context"
	"log"
	"time"

	"github.com/santichoks/stc-auth-service/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func NewMongoConnection(cfg *config.Config) *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	credential := options.Credential{
		Username: cfg.MongoUsername,
		Password: cfg.MongoPassword,
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoHost).SetAuth(credential))
	if err != nil {
		log.Fatalf("Database Connection Error : %s", err.Error())
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatalf("Database Ping Error : %s", err.Error())
	}

	return client
}
