package jit

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an error with a stable code and HTTP status, returned by the API as
// {"error":{"code":..., "message":...}}.
type Error struct {
	Code    string
	Status  int
	Message string
	// RequestID points at a related access request, e.g. the one that
	// already covers a duplicate submission.
	RequestID string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(status int, code, format string, args ...any) *Error {
	return &Error{Code: code, Status: status, Message: fmt.Sprintf(format, args...)}
}

func badRequest(format string, args ...any) *Error {
	return newErr(http.StatusBadRequest, "bad_request", format, args...)
}

func forbidden(format string, args ...any) *Error {
	return newErr(http.StatusForbidden, "forbidden", format, args...)
}

func notFound(format string, args ...any) *Error {
	return newErr(http.StatusNotFound, "not_found", format, args...)
}

func conflict(format string, args ...any) *Error {
	return newErr(http.StatusConflict, "conflict", format, args...)
}

func apiFailed(format string, args ...any) *Error {
	return newErr(http.StatusBadGateway, "tailscale_api_error", format, args...)
}

// AsError returns err as an *Error, wrapping unknown errors as internal.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newErr(http.StatusInternalServerError, "internal", "%v", err)
}
