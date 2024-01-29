package jwt_package

import (
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

func currentDateTime() *jwt.NumericDate {
	location, _ := time.LoadLocation("Asia/Bangkok")
	return jwt.NewNumericDate(time.Now().In(location))
}

func expiredDateTime(t int64) *jwt.NumericDate {
	location, _ := time.LoadLocation("Asia/Bangkok")
	return jwt.NewNumericDate(time.Now().In(location).Add(time.Duration(t) * time.Second))
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
