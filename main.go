package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/controllers"
	"github.com/santichoks/stc-auth-service/databases"
	"github.com/santichoks/stc-auth-service/repositories"
	"github.com/santichoks/stc-auth-service/router"
	"github.com/santichoks/stc-auth-service/services"
)

func main() {
	// Initial Configs
	cfg := config.GetConfig()

	// MongoDB and Redis Connection
	mongo := databases.NewMongoConnection(&cfg)
	redis := databases.NewRedisConnection(&cfg)
	defer mongo.Disconnect(context.Background())
	defer redis.Close()

	authMongoRepo := repositories.NewAuthMongoRepository(mongo)
	authRedisRepo := repositories.NewAuthRedisRepository(redis)
	authSrv := services.NewAuthService(authMongoRepo, authRedisRepo)
	authCtrl := controllers.NewAuthController(authSrv, &cfg)

	// Initial Fiber Server
	app := fiber.New()

	// Initial CORS request
	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowOrigins,
		AllowMethods:     strings.Join([]string{fiber.MethodGet, fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete}, ","),
		AllowHeaders:     cfg.AllowHeaders,
		AllowCredentials: true,
	}))

	// Initial Routes
	router.AuthRoute(app, authCtrl)

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		app.Shutdown()
	}()

	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
