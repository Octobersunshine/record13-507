package utils

import (
	"fmt"
	"math/rand"
	"time"
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func SuccessResponse(data interface{}) Response {
	return Response{
		Code:    200,
		Message: "success",
		Data:    data,
	}
}

func ErrorResponse(code int, message string) Response {
	return Response{
		Code:    code,
		Message: message,
		Data:    nil,
	}
}

func GenerateRequestNo() string {
	now := time.Now()
	return fmt.Sprintf("REQ%s%06d", now.Format("20060102150405"), rand.Intn(1000000))
}

func GenerateSessionID() string {
	now := time.Now()
	return fmt.Sprintf("SESS%s%06d", now.Format("20060102150405"), rand.Intn(1000000))
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
