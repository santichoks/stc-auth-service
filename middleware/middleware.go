package middleware

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/pkgs/jwtPkg"
	"github.com/santichoks/stc-auth-service/pkgs/responsePkg"
	"github.com/santichoks/stc-auth-service/repositories"
)

type GatewayMiddleware interface {
	VerifyToken(c *fiber.Ctx) error
}

type gatewayMiddleware struct {
	redis repositories.AuthRedisRepository
	cfg   *config.Config
}

func NewGatewayMiddleware(redis repositories.AuthRedisRepository, cfg *config.Config) GatewayMiddleware {
	return gatewayMiddleware{
		redis: redis,
		cfg:   cfg,
	}
}

func (m gatewayMiddleware) VerifyToken(c *fiber.Ctx) error {
	accessToken := c.Cookies("X-Access-Token")
	refreshToken := c.Cookies("X-Refresh-Token")

	var err error
	_, err = m.redis.Get(accessToken)
	if err != nil && err != redis.Nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	if err == nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, errors.New("invalid accessToken token"))
	}

	_, err = m.redis.Get(refreshToken)
	if err != nil && err != redis.Nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	if err == nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, errors.New("invalid refreshToken token"))
	}

	_, accessTokenErr := jwtPkg.ParseToken(accessToken, m.cfg.Jwt.AccessTokenSecret)
	refreshTokenClaims, refreshTokenErr := jwtPkg.ParseToken(refreshToken, m.cfg.Jwt.RefreshTokenSecret)
	// access token is expired, but the refresh token still exists.
	// hence, generate new tokens, both an access token and a refresh token.
	if accessTokenErr == jwt.ErrTokenExpired && refreshTokenErr == nil {
		myClaims := jwtPkg.MyClaims{
			UserId:    refreshTokenClaims.ID,
			Email:     refreshTokenClaims.Email,
			FirstName: refreshTokenClaims.FirstName,
			LastName:  refreshTokenClaims.LastName,
		}

		newAccessToken := jwtPkg.InitAccessToken(m.cfg.Jwt.AccessTokenSecret, m.cfg.Jwt.AccessTokenDuration, &myClaims)
		newRefreshToken := jwtPkg.InitRefreshToken(m.cfg.Jwt.RefreshTokenSecret, m.cfg.Jwt.RefreshTokenDuration, &myClaims)

		c.Cookie(&fiber.Cookie{
			Name:     "X-Access-Token",
			Value:    newAccessToken.SignToken(),
			Secure:   true,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteNoneMode,
		})

		c.Cookie(&fiber.Cookie{
			Name:     "X-Refresh-Token",
			Value:    newRefreshToken.SignToken(),
			Secure:   true,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteNoneMode,
		})
	}

	if refreshTokenErr != nil && refreshTokenErr != jwt.ErrTokenExpired {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, refreshTokenErr)
	}

	if refreshTokenErr != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, refreshTokenErr)
	}

	return c.Next()
}
