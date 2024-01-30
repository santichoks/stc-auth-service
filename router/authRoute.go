package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/controllers"
)

func AuthRoute(r *fiber.App, controller controllers.AuthController) {
	r.Get("/healthz", controller.Healthz)
	r.Post("/login", controller.LoginCtrl)
	r.Post("/logout", controller.LogoutCtrl)
	r.Post("/signup", controller.SignupCtrl)
}
