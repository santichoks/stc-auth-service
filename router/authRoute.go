package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/controllers"
	"github.com/santichoks/stc-auth-service/middleware"
)

func AuthRoute(r *fiber.App, mdw middleware.GatewayMiddleware, ctrl controllers.AuthController) {
	r.All("/gateway/*", mdw.VerifyToken, ctrl.GatewayCtrl)
	r.Get("/healthz", ctrl.Healthz)
	r.Post("/login", ctrl.LoginCtrl)
	r.Post("/logout", ctrl.LogoutCtrl)
	r.Post("/signup", ctrl.SignupCtrl)
}
