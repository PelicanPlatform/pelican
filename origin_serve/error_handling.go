/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package origin_serve

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// ErrorHandler manages consistent error handling and HTTP status code mapping
type ErrorHandler struct {
	errorMap map[string]int
}

// NewErrorHandler creates a new error handler
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		errorMap: map[string]int{
			// Filesystem errors
			"permission denied":         http.StatusForbidden,
			"no such file or directory": http.StatusNotFound,
			"file exists":               http.StatusConflict,
			"is a directory":            http.StatusBadRequest,
			"invalid argument":          http.StatusBadRequest,
			"read only file system":     http.StatusForbidden,

			// I/O errors
			"io error":            http.StatusInternalServerError,
			"bad file descriptor": http.StatusInternalServerError,
			"connection refused":  http.StatusServiceUnavailable,
			"connection reset":    http.StatusServiceUnavailable,

			// Resource exhaustion
			"disk quota exceeded":              http.StatusInsufficientStorage,
			"too many open files":              http.StatusServiceUnavailable,
			"resource temporarily unavailable": http.StatusServiceUnavailable,

			// Authorization errors
			"unauthorized":  http.StatusUnauthorized,
			"forbidden":     http.StatusForbidden,
			"access denied": http.StatusForbidden,

			// Token errors
			"token expired":          http.StatusUnauthorized,
			"invalid token":          http.StatusUnauthorized,
			"issuer not trusted":     http.StatusUnauthorized,
			"unable to verify token": http.StatusUnauthorized,
		},
	}
}

// MapToHTTPStatus maps an error to an HTTP status code using proper error type checking
func (eh *ErrorHandler) MapToHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	// Use errors.Is for standard error comparisons (more reliable than string matching)
	if errors.Is(err, fs.ErrPermission) {
		return http.StatusForbidden
	}
	if errors.Is(err, fs.ErrNotExist) {
		return http.StatusNotFound
	}
	if errors.Is(err, fs.ErrExist) {
		return http.StatusConflict
	}
	if errors.Is(err, fs.ErrInvalid) {
		return http.StatusBadRequest
	}

	// Check for specific syscall errors using errors.As
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		// Check the underlying error
		if errors.Is(pathErr.Err, fs.ErrPermission) {
			return http.StatusForbidden
		}
		if errors.Is(pathErr.Err, fs.ErrNotExist) {
			return http.StatusNotFound
		}
		if errors.Is(pathErr.Err, fs.ErrExist) {
			return http.StatusConflict
		}
	}

	// Check for specific syscall error codes
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.EACCES, syscall.EPERM:
			return http.StatusForbidden
		case syscall.ENOENT:
			return http.StatusNotFound
		case syscall.EEXIST:
			return http.StatusConflict
		case syscall.EISDIR:
			return http.StatusBadRequest
		case syscall.EMFILE, syscall.ENFILE:
			return http.StatusServiceUnavailable
		case syscall.EDQUOT:
			return http.StatusInsufficientStorage
		case syscall.ECONNREFUSED:
			return http.StatusServiceUnavailable
		case syscall.EROFS:
			return http.StatusForbidden
		}
	}

	// Fall back to string-based matching for other error types (backward compatibility)
	errMsg := strings.ToLower(err.Error())

	// Check for exact matches first
	for pattern, code := range eh.errorMap {
		if strings.Contains(errMsg, strings.ToLower(pattern)) {
			return code
		}
	}

	// Default to internal server error for unknown errors
	return http.StatusInternalServerError
}

// LogError logs an error with appropriate context
func (eh *ErrorHandler) LogError(operation string, err error, args ...interface{}) {
	if err == nil {
		return
	}

	status := eh.MapToHTTPStatus(err)
	logEntry := log.WithFields(log.Fields{
		"operation":   operation,
		"http_status": status,
	})

	for i := 0; i < len(args)-1; i += 2 {
		if key, ok := args[i].(string); ok {
			logEntry = logEntry.WithField(key, args[i+1])
		}
	}

	// Log auth errors at warning level, others at error level
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		logEntry.Warnf("Authorization error: %v", err)
	} else if status >= 500 {
		logEntry.Errorf("Server error: %v", err)
	} else {
		logEntry.Infof("Client error: %v", err)
	}
}

// AuthError represents an authorization error with optional context
type AuthError struct {
	Code    int
	Message string
	Path    string
	User    string
	Issuer  string
	cause   error
}

// NewAuthError creates a new authorization error
func NewAuthError(code int, message string, path string) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Path:    path,
	}
}

// WithUser adds user information to the error
func (ae *AuthError) WithUser(user string) *AuthError {
	ae.User = user
	return ae
}

// WithIssuer adds issuer information to the error
func (ae *AuthError) WithIssuer(issuer string) *AuthError {
	ae.Issuer = issuer
	return ae
}

// WithCause adds the underlying error cause
func (ae *AuthError) WithCause(err error) *AuthError {
	ae.cause = err
	return ae
}

// Error implements the error interface
func (ae *AuthError) Error() string {
	if ae.cause != nil {
		return fmt.Sprintf("%s (caused by: %v)", ae.Message, ae.cause)
	}
	return ae.Message
}

// OperationError represents a file operation error with recovery hints
type OperationError struct {
	Operation   string
	Path        string
	HTTPStatus  int
	Message     string
	Recoverable bool
	cause       error
}

// NewOperationError creates a new operation error
func NewOperationError(operation, path string, err error) *OperationError {
	handler := NewErrorHandler()
	status := handler.MapToHTTPStatus(err)

	// Determine if error is recoverable
	recoverable := false
	if status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout ||
		strings.Contains(err.Error(), "temporarily") {
		recoverable = true
	}

	return &OperationError{
		Operation:   operation,
		Path:        path,
		HTTPStatus:  status,
		Message:     err.Error(),
		Recoverable: recoverable,
		cause:       err,
	}
}

// Error implements the error interface
func (oe *OperationError) Error() string {
	return fmt.Sprintf("%s failed on %s: %s", oe.Operation, oe.Path, oe.Message)
}

// String returns a detailed error description
func (oe *OperationError) String() string {
	result := fmt.Sprintf("[%d] %s\n  Operation: %s\n  Path: %s\n  Message: %s",
		oe.HTTPStatus, http.StatusText(oe.HTTPStatus), oe.Operation, oe.Path, oe.Message)

	if oe.Recoverable {
		result += "\n  Recoverable: true (retry recommended)"
	} else {
		result += "\n  Recoverable: false"
	}

	return result
}

// TokenValidationError represents token validation failures
type TokenValidationError struct {
	Reason   string
	Issuer   string
	Subject  string
	Code     int
	Details  string
	Verified bool // Whether the token signature was verified before extracting metadata
}

// NewTokenValidationError creates a new token validation error
func NewTokenValidationError(reason string) *TokenValidationError {
	return &TokenValidationError{
		Reason: reason,
		Code:   http.StatusUnauthorized,
	}
}

// WithIssuer adds issuer information
func (tve *TokenValidationError) WithIssuer(issuer string) *TokenValidationError {
	tve.Issuer = issuer
	return tve
}

// WithSubject adds subject information
func (tve *TokenValidationError) WithSubject(subject string) *TokenValidationError {
	tve.Subject = subject
	return tve
}

// WithDetails adds additional context details
func (tve *TokenValidationError) WithDetails(details string) *TokenValidationError {
	tve.Details = details
	return tve
}

// WithVerified marks whether the token was cryptographically verified before extracting metadata
func (tve *TokenValidationError) WithVerified(verified bool) *TokenValidationError {
	tve.Verified = verified
	return tve
}

// Error implements the error interface
func (tve *TokenValidationError) Error() string {
	return fmt.Sprintf("token validation failed: %s", tve.Reason)
}

// String returns a detailed error description
func (tve *TokenValidationError) String() string {
	result := fmt.Sprintf("[%d] %s\n  Reason: %s",
		tve.Code, http.StatusText(tve.Code), tve.Reason)

	// If token metadata (issuer/subject) was extracted without verification, make that clear
	verificationNote := ""
	if !tve.Verified && (tve.Issuer != "" || tve.Subject != "") {
		verificationNote = " (unverified)"
	}

	if tve.Issuer != "" {
		result += fmt.Sprintf("\n  Issuer%s: %s", verificationNote, tve.Issuer)
	}
	if tve.Subject != "" {
		result += fmt.Sprintf("\n  Subject%s: %s", verificationNote, tve.Subject)
	}
	if tve.Details != "" {
		result += fmt.Sprintf("\n  Details: %s", tve.Details)
	}

	return result
}

// PermissionDeniedError is a specialized authorization error
type PermissionDeniedError struct {
	Resource string
	Action   string
	Reason   string
}

// NewPermissionDeniedError creates a new permission denied error
func NewPermissionDeniedError(resource, action, reason string) *PermissionDeniedError {
	return &PermissionDeniedError{
		Resource: resource,
		Action:   action,
		Reason:   reason,
	}
}

// Error implements the error interface
func (pde *PermissionDeniedError) Error() string {
	return fmt.Sprintf("permission denied: cannot %s %s (%s)", pde.Action, pde.Resource, pde.Reason)
}

// HTTPStatus returns the appropriate HTTP status code
func (pde *PermissionDeniedError) HTTPStatus() int {
	return http.StatusForbidden
}

// NotFoundError is a specialized error for missing resources
type NotFoundError struct {
	ResourceType string
	ResourcePath string
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(resourceType, resourcePath string) *NotFoundError {
	return &NotFoundError{
		ResourceType: resourceType,
		ResourcePath: resourcePath,
	}
}

// Error implements the error interface
func (nfe *NotFoundError) Error() string {
	return fmt.Sprintf("%s not found: %s", nfe.ResourceType, nfe.ResourcePath)
}

// HTTPStatus returns the appropriate HTTP status code
func (nfe *NotFoundError) HTTPStatus() int {
	return http.StatusNotFound
}

// ResourceExhaustedError represents resource limit violations
type ResourceExhaustedError struct {
	ResourceType string
	Message      string
}

// NewResourceExhaustedError creates a new resource exhausted error
func NewResourceExhaustedError(resourceType, message string) *ResourceExhaustedError {
	return &ResourceExhaustedError{
		ResourceType: resourceType,
		Message:      message,
	}
}

// Error implements the error interface
func (ree *ResourceExhaustedError) Error() string {
	return fmt.Sprintf("resource exhausted: %s - %s", ree.ResourceType, ree.Message)
}

// HTTPStatus returns the appropriate HTTP status code
func (ree *ResourceExhaustedError) HTTPStatus() int {
	return http.StatusInsufficientStorage
}
