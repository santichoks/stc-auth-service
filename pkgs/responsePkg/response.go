package responsePkg

import (
	"github.com/gofiber/fiber/v2"
)

type msgResponse struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

func SuccessResponse(c *fiber.Ctx, statusCode int, data any) error {
	if v, ok := data.(string); ok {
		return c.Status(statusCode).JSON(msgResponse{
			StatusCode: statusCode,
			Message:    v,
		})
	}

	return c.Status(statusCode).JSON(data)
}

func ErrorResponse(c *fiber.Ctx, statusCode int, err error) error {
	return c.Status(statusCode).JSON(msgResponse{
		StatusCode: statusCode,
		Message:    err.Error(),
	})
}
