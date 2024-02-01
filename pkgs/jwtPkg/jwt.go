package jwtPkg

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MyClaims struct {
	UserId    string
	Email     string
	FirstName string
	LastName  string
}

type ClaimsWithOriginal struct {
	*MyClaims
	jwt.RegisteredClaims
}

type Claims struct {
	Secret []byte
	*ClaimsWithOriginal
}

func (a Claims) SignToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, a.ClaimsWithOriginal)
	tokenString, _ := token.SignedString([]byte(a.Secret))
	return tokenString
}

func ParseToken(tokenString string, secret string) (*ClaimsWithOriginal, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ClaimsWithOriginal{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if tokenDetail, ok := token.Claims.(*ClaimsWithOriginal); ok {
		return tokenDetail, nil
	}

	return nil, errors.New("claims type is invalid")
}

func currentDateTime() *jwt.NumericDate {
	return jwt.NewNumericDate(time.Now())
}

func expiredDateTime(t int64) *jwt.NumericDate {
	return jwt.NewNumericDate(time.Now().Add(time.Duration(t) * time.Second))
}

func InitAccessToken(secret string, expiredAt int64, myClaims *MyClaims) *Claims {
	return &Claims{
		Secret: []byte(secret),
		ClaimsWithOriginal: &ClaimsWithOriginal{
			MyClaims: myClaims,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "STC",
				Subject:   "AccessToken",
				Audience:  []string{"STC"},
				ExpiresAt: expiredDateTime(expiredAt),
				NotBefore: currentDateTime(),
				IssuedAt:  currentDateTime(),
			},
		},
	}
}

func InitRefreshToken(secret string, expiredAt int64, myClaims *MyClaims) *Claims {
	return &Claims{
		Secret: []byte(secret),
		ClaimsWithOriginal: &ClaimsWithOriginal{
			MyClaims: myClaims,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "STC",
				Subject:   "RefreshToken",
				Audience:  []string{"STC"},
				ExpiresAt: expiredDateTime(expiredAt),
				NotBefore: currentDateTime(),
				IssuedAt:  currentDateTime(),
			},
		},
	}
}
