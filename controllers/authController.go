package controllers

import (
	"fmt"

	"github.com/go-playground/validator"
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/services"
)

type AuthController interface {
	Healthz(*fiber.Ctx) error
	SignUpCtrl(*fiber.Ctx) error
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

var validate = validator.New()

func Validate(data interface{}) {
	errs := validate.Struct(data)
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			fmt.Println(err.Field())
		}
	}
}

func (ctrl authController) Healthz(c *fiber.Ctx) error {
	response := map[string]any{
		"message": "Healthy",
		"status":  fiber.StatusOK,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func (ctrl authController) SignUpCtrl(c *fiber.Ctx) error {
	var req models.SignUpReq
	if err := c.BodyParser(&req); err != nil {
		return err
	}

	ctrl.srv.SignUpSrv(req, ctrl.cfg)
	return nil
}
