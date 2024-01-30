package error_package

type ErrorResp struct {
	Message string `json:"message"`
}

func ErrorResponse(err error) ErrorResp {
	return ErrorResp{
		Message: err.Error(),
	}
}
