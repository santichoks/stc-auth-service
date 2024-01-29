package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserInfo struct {
	Id        primitive.ObjectID `bson:"_id,omitempty"`
	FirstName string             `bson:"firstName"`
	LastName  string             `bson:"lastName"`
	Email     string             `bson:"email"`
	Password  string             `bson:"password"`
	CreatedAt time.Time          `bson:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt"`
}

type SignUpReq struct {
	FirstName string `json:"firstName" validate:"required,alphanum,min=1,max=50"`
	LastName  string `json:"lastName" validate:"required,alphanum,min=1,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,alphanum,min=8"`
}
