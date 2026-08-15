package middleware

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// TracingMiddleware injects trace_id/correlation_id into the gin context and logs requests.
func TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := c.GetHeader("X-Trace-Id")
		if traceID == "" {
			traceID = generateTraceID()
		}
		correlationID := c.GetHeader("X-Correlation-Id")
		tenantID := c.GetHeader("X-Tenant-Id")
		if tenantID == "" {
			tenantID = "default"
		}

		c.Set("trace_id", traceID)
		c.Set("correlation_id", correlationID)
		c.Set("tenant_id", tenantID)
		c.Set("request_id", traceID)

		// Add trace headers to response
		c.Header("X-Trace-Id", traceID)
		if correlationID != "" {
			c.Header("X-Correlation-Id", correlationID)
		}

		c.Next()

		// Log request
		status := c.Writer.Status()
		slog.InfoContext(c.Request.Context(), "request completed",
			slog.String("trace_id", traceID),
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", status),
			slog.String("ip", c.ClientIP()),
		)

		_ = traceID // used above for logging
	}
}

func generateTraceID() string {
	// Simple trace ID generation — in production use a proper UUID or trace ID generator
	return fmt.Sprintf("trace-%d", time.Now().UnixNano())
}
