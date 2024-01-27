package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/controllers"
)

func AuthRoute(r *fiber.App, controller controllers.AuthController) {
	r.Get("/healthz", controller.Healthz)
}
