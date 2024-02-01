package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/pkgs/responsePkg"

	"github.com/santichoks/stc-auth-service/services"
)

type AuthController interface {
	Healthz(*fiber.Ctx) error
	GatewayCtrl(c *fiber.Ctx) error
	LoginCtrl(*fiber.Ctx) error
	LogoutCtrl(c *fiber.Ctx) error
	SignupCtrl(*fiber.Ctx) error
}

type authController struct {
	srv services.AuthService
	cfg *config.Config
}

func NewAuthController(authSrv services.AuthService, cfg *config.Config) AuthController {
	return authController{
		srv: authSrv,
		cfg: cfg,
	}
}

func (ctrl authController) Healthz(c *fiber.Ctx) error {
	return responsePkg.SuccessResponse(c, fiber.StatusOK, "healthy")
}

func (ctrl authController) GatewayCtrl(c *fiber.Ctx) error {
	return nil
}

func (ctrl authController) LoginCtrl(c *fiber.Ctx) error {
	var req models.LoginReq
	if err := c.BodyParser(&req); err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	response, err := ctrl.srv.LoginSrv(req, ctrl.cfg)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "X-Access-Token",
		Value:    response.AccessToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
	})

	c.Cookie(&fiber.Cookie{
		Name:     "X-Refresh-Token",
		Value:    response.RefreshToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
	})

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}

func (ctrl authController) LogoutCtrl(c *fiber.Ctx) error {
	accessToken := c.Cookies("X-Access-Token")
	refreshToken := c.Cookies("X-Refresh-Token")

	err := ctrl.srv.LogoutSrv(accessToken, refreshToken, ctrl.cfg)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}

func (ctrl authController) SignupCtrl(c *fiber.Ctx) error {
	var req models.SignupReq
	if err := c.BodyParser(&req); err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	response, err := ctrl.srv.SignupSrv(req, ctrl.cfg)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	return responsePkg.SuccessResponse(c, fiber.StatusOK, response)
}
