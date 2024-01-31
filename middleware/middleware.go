package middleware

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
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

	_, err = jwtPkg.ParseToken(accessToken, m.cfg.Jwt.AccessTokenSecret)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}
	_, err = jwtPkg.ParseToken(refreshToken, m.cfg.Jwt.RefreshTokenSecret)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	// TODO //
	fmt.Println("PASS")
	// TODO //

	return c.Next()
}
