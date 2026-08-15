package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// AuditMiddleware logs audit events for state-changing operations.
func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only audit mutating operations
		method := c.Request.Method
		if method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
			c.Next()
			return
		}

		traceID := getTraceID(c)
		ctx := GetCognitoContext(c)
		userEmail := ""
		if ctx != nil {
			userEmail = ctx.Email
		}

		// Record start time
		start := time.Now()
		c.Next()
		elapsed := time.Since(start)

		status := c.Writer.Status()

		// Log audit event for mutations
		if status >= 200 && status < 400 {
			slog.InfoContext(c.Request.Context(), "audit: mutation successful",
				slog.String("trace_id", traceID),
				slog.String("user", userEmail),
				slog.String("method", method),
				slog.String("path", c.Request.URL.Path),
				slog.Int("status", status),
				slog.Int64("latency_ms", elapsed.Milliseconds()),
			)
		} else if status >= 400 {
			slog.WarnContext(c.Request.Context(), "audit: mutation failed",
				slog.String("trace_id", traceID),
				slog.String("user", userEmail),
				slog.String("method", method),
				slog.String("path", c.Request.URL.Path),
				slog.Int("status", status),
				slog.Int64("latency_ms", elapsed.Milliseconds()),
			)
		}
	}
}

func getTraceID(c *gin.Context) string {
	val, _ := c.Get("trace_id")
	if s, ok := val.(string); ok {
		return s
	}
	return "-"
}
