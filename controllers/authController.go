package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	error_package "github.com/santichoks/stc-auth-service/pkgs/errorPackage"
	"github.com/santichoks/stc-auth-service/services"
)

type AuthController interface {
	Healthz(*fiber.Ctx) error
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
	response := map[string]any{
		"message": "Healthy",
		"status":  fiber.StatusOK,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func (ctrl authController) LoginCtrl(c *fiber.Ctx) error {
	var req models.LoginReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(error_package.ErrorResponse(err))
	}

	response, err := ctrl.srv.LoginSrv(req, ctrl.cfg)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(error_package.ErrorResponse(err))
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func (ctrl authController) LogoutCtrl(c *fiber.Ctx) error {
	accessToken := c.Get("X-Access-Token")
	refreshToken := c.Get("X-Refresh-Token")

	err := ctrl.srv.LogoutSrv(accessToken, refreshToken)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(error_package.ErrorResponse(err))
	}

	return c.Status(fiber.StatusOK).JSON(nil)
}

func (ctrl authController) SignupCtrl(c *fiber.Ctx) error {
	var req models.SignupReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(error_package.ErrorResponse(err))
	}

	response, err := ctrl.srv.SignupSrv(req, ctrl.cfg)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(error_package.ErrorResponse(err))
	}

	return c.Status(fiber.StatusOK).JSON(response)
}
