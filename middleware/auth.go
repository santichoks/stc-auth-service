package middleware

import (
	"encoding/json"
	"errors"
	"strings"

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
	accessToken := c.Cookies("accessToken")
	_, err := m.redis.Get(accessToken)
	if err != nil && !errors.Is(err, redis.Nil) {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}
	if err == nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, errors.New("invalid access token"))
	}

	accessTokenClaims, err := jwtPkg.ParseToken(accessToken, m.cfg.Jwt.AccessTokenSecret)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		refreshToken := c.Cookies("refreshToken")
		_, err = m.redis.Get(refreshToken)
		if err != nil && !errors.Is(err, redis.Nil) {
			return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
		}

		if err == nil {
			return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, errors.New("invalid refresh token"))
		}

		refreshTokenClaims, err := jwtPkg.ParseToken(refreshToken, m.cfg.Jwt.RefreshTokenSecret)
		if err != nil {
			return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
		}

		myClaims := jwtPkg.MyClaims{
			UserId:    refreshTokenClaims.ID,
			Email:     refreshTokenClaims.Email,
			FirstName: refreshTokenClaims.FirstName,
			LastName:  refreshTokenClaims.LastName,
		}

		newAccessToken := jwtPkg.InitAccessToken(m.cfg.Jwt.AccessTokenSecret, m.cfg.Jwt.AccessTokenDuration, &myClaims)
		newRefreshToken := jwtPkg.InitRefreshToken(m.cfg.Jwt.RefreshTokenSecret, m.cfg.Jwt.RefreshTokenDuration, &myClaims)

		c.Cookie(&fiber.Cookie{
			Name:     "accessToken",
			Value:    newAccessToken.SignToken(),
			Secure:   true,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteNoneMode,
			// TO-DO must set an expiration date.
		})

		c.Cookie(&fiber.Cookie{
			Name:     "refreshToken",
			Value:    newRefreshToken.SignToken(),
			Secure:   true,
			HTTPOnly: true,
			SameSite: fiber.CookieSameSiteNoneMode,
			// TO-DO must set an expiration date.
		})

		accessTokenClaims = newAccessToken.ClaimsWithOriginal
	}

	user, _ := json.Marshal(jwtPkg.MyClaims{
		UserId:    accessTokenClaims.ID,
		Email:     accessTokenClaims.Email,
		FirstName: accessTokenClaims.FirstName,
		LastName:  accessTokenClaims.LastName,
	})

	var serviceUri string
	path := strings.TrimPrefix(c.Path(), "/gateway")
	for i := range m.cfg.ServiceLists {
		serviceHost := m.cfg.ServiceLists[i].Host
		serviceAlias := m.cfg.ServiceLists[i].Alias
		if strings.HasPrefix(path, serviceAlias) {
			serviceUri = serviceHost + strings.TrimPrefix(path, serviceAlias)
			break
		}
	}

	c.Request().Header.Set("X-Uri", serviceUri)
	c.Request().Header.Set("X-User", string(user))

	return c.Next()
}
