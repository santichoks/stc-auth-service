package controllers

import (
	"encoding/json"

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
	ResetPasswordCtrl(*fiber.Ctx) error
	ChangePasswordCtrl(*fiber.Ctx) error
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
	serviceUri := c.Get("X-Uri")
	serviceMethod := c.Method()
	serviceBody := c.Body()

	agent := fiber.AcquireAgent()
	agent.Request().Header.SetRequestURI(serviceUri)
	agent.Request().Header.SetMethod(serviceMethod)
	agent.Request().SetBody(serviceBody)
	agent.Set("X-User", c.Get("X-User"))
	if err := agent.Parse(); err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadGateway, fiber.ErrBadGateway)
	}

	statusCode, data, errs := agent.Bytes()
	if errs != nil || len(errs) > 0 {
		return responsePkg.ErrorResponse(c, fiber.StatusBadGateway, fiber.ErrBadGateway)
	}

	var response map[string]json.RawMessage
	err := json.Unmarshal(data, &response)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadGateway, fiber.ErrBadGateway)
	}

	return c.Status(statusCode).JSON(response)
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
		Name:     "accessToken",
		Value:    response.AccessToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
		// TO-DO must set an expiration date.
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refreshToken",
		Value:    response.RefreshToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
		// TO-DO must set an expiration date.
	})

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}

func (ctrl authController) LogoutCtrl(c *fiber.Ctx) error {
	accessToken := c.Cookies("accessToken")
	refreshToken := c.Cookies("refreshToken")

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

	c.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    response.AccessToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
		// TO-DO must set an expiration date.
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refreshToken",
		Value:    response.RefreshToken,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteNoneMode,
		// TO-DO must set an expiration date.
	})

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}

func (ctrl authController) ResetPasswordCtrl(c *fiber.Ctx) error {
	var req models.ResetPasswordReq
	if err := c.BodyParser(&req); err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	err := ctrl.srv.ResetPasswordSrv(req, ctrl.cfg)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}

func (ctrl authController) ChangePasswordCtrl(c *fiber.Ctx) error {
	resetPasswordToken := c.Query("token")
	accessToken := c.Cookies("accessToken")

	var req models.ChangePasswordReq
	if err := c.BodyParser(&req); err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusBadRequest, err)
	}

	err := ctrl.srv.ChangePasswordSrv(req, resetPasswordToken, accessToken, ctrl.cfg)
	if err != nil {
		return responsePkg.ErrorResponse(c, fiber.StatusUnauthorized, err)
	}

	return responsePkg.SuccessResponse(c, fiber.StatusOK, "successfully")
}
