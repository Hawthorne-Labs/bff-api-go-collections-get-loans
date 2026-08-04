package middleware

import (
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
			c.Logger().Info("audit: mutation successful",
				gin.LogFields{
					{Key: "trace_id", Value: traceID},
					{Key: "user", Value: userEmail},
					{Key: "method", Value: method},
					{Key: "path", Value: c.Request.URL.Path},
					{Key: "status", Value: status},
					{Key: "latency_ms", Value: elapsed.Milliseconds()},
				},
			)
		} else if status >= 400 {
			c.Logger().Warn("audit: mutation failed",
				gin.LogFields{
					{Key: "trace_id", Value: traceID},
					{Key: "user", Value: userEmail},
					{Key: "method", Value: method},
					{Key: "path", Value: c.Request.URL.Path},
					{Key: "status", Value: status},
					{Key: "latency_ms", Value: elapsed.Milliseconds()},
				},
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
