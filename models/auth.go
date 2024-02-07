package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	Id        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FirstName string             `bson:"firstName" json:"firstName"`
	LastName  string             `bson:"lastName" json:"lastName"`
	Email     string             `bson:"email" json:"email"`
	Password  string             `bson:"password" json:"-"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt" json:"updatedAt"`
}

type LoginReq struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,alphanum,min=8"`
}

type SignupReq struct {
	FirstName string `json:"firstName" validate:"required,alphanum,min=1,max=50"`
	LastName  string `json:"lastName" validate:"required,alphanum,min=1,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,alphanum,min=8"`
}

type TokenRes struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type ResetPasswordReq struct {
	Email string `json:"email" validate:"required,email"`
}

type ChangePasswordReq struct {
	OldPassword string `json:"oldPassword" validate:"required,alphanum,min=8"`
	NewPassword string `json:"newPassword" validate:"required,alphanum,min=8"`
}
