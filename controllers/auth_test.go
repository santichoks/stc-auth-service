package controllers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/santichoks/stc-auth-service/config"
	"github.com/santichoks/stc-auth-service/controllers"
	"github.com/santichoks/stc-auth-service/models"
	"github.com/santichoks/stc-auth-service/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHealthz(t *testing.T) {
	authSrv := services.NewAuthServiceMock()

	authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

	app := fiber.New()
	app.Get("/healthz", authCtrl.Healthz)

	req := httptest.NewRequest("GET", "/healthz", nil)

	res, _ := app.Test(req)
	defer res.Body.Close()

	if assert.Equal(t, fiber.StatusOK, res.StatusCode) {
		type msgResponse struct {
			StatusCode int    `json:"statusCode"`
			Message    string `json:"message"`
		}

		var data msgResponse
		body, _ := io.ReadAll(res.Body)
		json.Unmarshal(body, &data)

		assert.Equal(t, fiber.StatusOK, data.StatusCode)
		assert.Equal(t, "healthy", data.Message)
	}
}

func TestGatewayCtrl(t *testing.T) {
	t.Run("GatewayCtrl Successful", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Get("/gateway/*", authCtrl.GatewayCtrl)

		req := httptest.NewRequest("GET", "/gateway/api/v2/pokemon/", nil)
		req.Header.Set("X-Url", "https://pokeapi.co")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
	})

	t.Run("GatewayCtrl Parse Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Get("/gateway/*", authCtrl.GatewayCtrl)

		req := httptest.NewRequest("GET", "/gateway/api/v2/pokemon/", nil)
		req.Header.Set("X-Url", "app://pokeapi.co")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusBadGateway, res.StatusCode)
	})

	t.Run("GatewayCtrl Bytes Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Get("/gateway/*", authCtrl.GatewayCtrl)

		req := httptest.NewRequest("GET", "/gateway/api/v2/pokemon/", nil)
		req.Header.Set("X-Url", "pokeapi.co")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusBadGateway, res.StatusCode)
	})

	t.Run("GatewayCtrl Unmarshal Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Get("/gateway/*", authCtrl.GatewayCtrl)

		req := httptest.NewRequest("GET", "/gateway/api/v2/pokemon/", nil)
		req.Header.Set("X-Url", "http://restapi.adequateshop.com/api/Traveler/14841")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusBadGateway, res.StatusCode)
	})
}

func TestLoginCtrl(t *testing.T) {
	body := models.LoginReq{
		Email:    "santichok@stc.com",
		Password: "123456",
	}

	bodyJson, _ := json.Marshal(body)

	t.Run("LoginCtrl Successful", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Post("/login", authCtrl.LoginCtrl)
		authSrv.On("LoginSrv", body, &config.Config{}).Return(&models.TokenRes{}, nil)
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(bodyJson))
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
	})

	t.Run("LoginCtrl Parse Body Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Post("/login", authCtrl.LoginCtrl)
		req := httptest.NewRequest("POST", "/login", nil)
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusBadRequest, res.StatusCode)
	})

	t.Run("LoginCtrl LoginSrv Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})

		app := fiber.New()
		app.Post("/login", authCtrl.LoginCtrl)
		authSrv.On("LoginSrv", body, &config.Config{}).Return(&models.TokenRes{}, errors.New(""))
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(bodyJson))
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)
		defer res.Body.Close()

		assert.Equal(t, fiber.StatusUnauthorized, res.StatusCode)
	})
}

func TestLogoutCtrl(t *testing.T) {
	t.Run("LogoutCtrl Logout Successful", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authSrv.On("LogoutSrv", mock.Anything, mock.Anything, &config.Config{}).Return(nil)

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})
		app := fiber.New()
		app.Post("/logout", authCtrl.LogoutCtrl)

		req := httptest.NewRequest("POST", "/logout", nil)
		res, _ := app.Test(req)

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
	})

	t.Run("LogoutCtrl LogoutSrv Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authSrv.On("LogoutSrv", mock.Anything, mock.Anything, &config.Config{}).Return(errors.New(""))

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})
		app := fiber.New()
		app.Post("/logout", authCtrl.LogoutCtrl)

		req := httptest.NewRequest("POST", "/logout", nil)
		res, _ := app.Test(req)

		assert.Equal(t, fiber.StatusBadRequest, res.StatusCode)
	})
}

func TestSignupCtrl(t *testing.T) {
	body := models.SignupReq{
		FirstName: "santichok",
		LastName:  "sangarun",
		Email:     "santichok@stc.com",
		Password:  "12345678",
	}

	bodyJson, _ := json.Marshal(body)
	t.Run("SignupCtrl Successful", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authSrv.On("SignupSrv", models.SignupReq{
			FirstName: "santichok",
			LastName:  "sangarun",
			Email:     "santichok@stc.com",
			Password:  "12345678",
		}, &config.Config{}).Return(&models.TokenRes{}, nil)

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})
		app := fiber.New()
		app.Post("/signup", authCtrl.SignupCtrl)

		req := httptest.NewRequest("POST", "/signup", bytes.NewReader(bodyJson))
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
	})

	t.Run("SignupCtrl Parse Body Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authSrv.On("SignupSrv", models.SignupReq{
			FirstName: "santichok",
			LastName:  "sangarun",
			Email:     "santichok@stc.com",
			Password:  "12345678",
		}, &config.Config{}).Return(&models.TokenRes{}, nil)

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})
		app := fiber.New()
		app.Post("/signup", authCtrl.SignupCtrl)

		req := httptest.NewRequest("POST", "/signup", nil)
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)

		assert.Equal(t, fiber.StatusBadRequest, res.StatusCode)
	})

	t.Run("SignupCtrl SignupSrv Failed", func(t *testing.T) {
		authSrv := services.NewAuthServiceMock()
		authSrv.On("SignupSrv", models.SignupReq{
			FirstName: "santichok",
			LastName:  "sangarun",
			Email:     "santichok@stc.com",
			Password:  "12345678",
		}, &config.Config{}).Return(&models.TokenRes{}, errors.New(""))

		authCtrl := controllers.NewAuthController(authSrv, &config.Config{})
		app := fiber.New()
		app.Post("/signup", authCtrl.SignupCtrl)

		req := httptest.NewRequest("POST", "/signup", bytes.NewReader(bodyJson))
		req.Header.Set("Content-Type", "application/json")
		res, _ := app.Test(req)

		assert.Equal(t, fiber.StatusBadRequest, res.StatusCode)
	})
}
