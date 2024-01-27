package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/services"
)

type AuthController interface {
	Healthz(*fiber.Ctx) error
}

type authController struct {
	srv services.AuthService
}

func NewAuthController(authSrv services.AuthService) AuthController {
	return authController{
		srv: authSrv,
	}
}

func (ctl authController) Healthz(c *fiber.Ctx) error {
	response := map[string]any{
		"message": "Healthy",
		"status":  fiber.StatusOK,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}
