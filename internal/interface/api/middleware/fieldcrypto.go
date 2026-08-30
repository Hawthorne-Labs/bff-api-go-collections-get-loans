package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/fieldcrypto"
)

// FieldCryptoMiddlewareConfig wires field-value crypto middleware.
type FieldCryptoMiddlewareConfig struct {
	Enabled        bool
	Service        *fieldcrypto.FieldCryptoService
	Policy         *fieldcrypto.CryptoPolicy
	Settings       *fieldcrypto.CryptoSettings
	SessionManager any
	TenantAuthority fieldcrypto.TenantAuthority
}

// FieldCryptoMiddleware decrypts request bodies and encrypts 2xx JSON responses for policy-matched routes.
func FieldCryptoMiddleware(cfg FieldCryptoMiddlewareConfig) gin.HandlerFunc {
	if !cfg.Enabled || cfg.Settings == nil || cfg.Policy == nil || cfg.Service == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	if cfg.TenantAuthority == nil {
		cfg.TenantAuthority = fieldcrypto.GetTenantAuthority()
	}

	return func(c *gin.Context) {
		rule := cfg.Policy.Resolve(c.Request.Method, c.Request.URL.Path)
		if rule == nil || !cfg.Settings.Enabled {
			c.Next()
			return
		}

		sessionID := c.GetHeader("X-Crypto-Session-Id")
		token := c.GetHeader("X-Crypto-Access-Token")
		if sessionID == "" || cfg.SessionManager == nil {
			abortFieldCrypto(c, fieldcrypto.NewSessionInvalid())
			return
		}

		service := cfg.Service
		mode := fieldcrypto.SessionManagerMode(cfg.SessionManager)
		switch mode {
		case "stateless":
			mgr, ok := cfg.SessionManager.(*fieldcrypto.StatelessCryptoSessionManager)
			if !ok {
				abortFieldCrypto(c, fieldcrypto.NewSessionInvalid())
				return
			}
			authorized, err := cfg.TenantAuthority.Resolve(
				c.Request.Context(),
				c.GetHeader("Authorization"),
				c.GetHeader("X-Tenant-Id"),
				"",
				false,
				c.GetHeader("X-Trace-Id"),
			)
			if err != nil {
				abortFieldCrypto(c, err)
				return
			}
			verified, err := mgr.Resolve(token, sessionID, authorized.TenantDigest, c.GetHeader("Authorization"), mgr.Namespace())
			if err != nil {
				abortFieldCrypto(c, err)
				return
			}
			provider, err := fieldcrypto.NewFixedSessionKeyProvider(verified.SessionID, verified.SessionKey)
			if err != nil {
				abortFieldCrypto(c, err)
				return
			}
			service = fieldcrypto.NewFieldCryptoService(provider)
		default:
			mgr, ok := cfg.SessionManager.(*fieldcrypto.CryptoSessionManager)
			if !ok {
				abortFieldCrypto(c, fieldcrypto.NewSessionInvalid())
				return
			}
			if !mgr.VerifyAccessToken(token, sessionID) {
				abortFieldCrypto(c, fieldcrypto.NewSessionInvalid())
				return
			}
			sessionKey, err := mgr.SessionKey(sessionID)
			if err != nil {
				abortFieldCrypto(c, err)
				return
			}
			if sessionKey == nil {
				abortFieldCrypto(c, fieldcrypto.NewSessionInvalid())
				return
			}
		}

		ctx := fieldcrypto.CryptoContext{
			KID:       sessionID,
			RequestID: c.GetHeader("X-Request-Id"),
			TraceID:   c.GetHeader("X-Trace-Id"),
			Endpoint:  c.Request.URL.Path,
			Method:    c.Request.Method,
		}

		if rule.DecryptRequest {
			ctx.Direction = "decrypt"
			if err := decryptRequestBody(c, service, ctx, cfg.Settings.MaxPayloadSize); err != nil {
				abortFieldCrypto(c, err)
				return
			}
		}

		if !rule.EncryptResponse {
			c.Next()
			return
		}

		ctx.Direction = "encrypt"
		capture := &fieldCryptoResponseWriter{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = capture
		c.Next()

		status := capture.Status()
		if status == 0 {
			status = http.StatusOK
		}
		if status < 200 || status >= 300 || !isJSONContentType(capture.Header().Get("Content-Type")) {
			capture.flushRaw()
			return
		}

		var payload any
		if capture.body.Len() > 0 {
			if err := json.Unmarshal(capture.body.Bytes(), &payload); err != nil {
				abortFieldCrypto(c, fieldcrypto.NewEncryptionFailed())
				return
			}
		} else {
			payload = map[string]any{}
		}
		sealed, err := service.EncryptJSON(payload, ctx)
		if err != nil {
			abortFieldCrypto(c, fieldcrypto.NewEncryptionFailed())
			return
		}
		out, err := json.Marshal(sealed)
		if err != nil {
			abortFieldCrypto(c, fieldcrypto.NewEncryptionFailed())
			return
		}
		count := fieldcrypto.CountScalars(payload)
		c.Header("X-Crypto-Mode", cfg.Settings.Mode)
		c.Header("X-Crypto-Version", cfg.Settings.Version)
		c.Header("X-Crypto-Kid", sessionID)
		c.Header("X-Encrypted-Fields-Count", itoa(count))
		c.Header("Content-Type", "application/json")
		c.Header("Content-Length", itoa(len(out)))
		c.Writer = capture.ResponseWriter
		c.Writer.WriteHeader(status)
		_, _ = c.Writer.Write(out)
		logFieldCrypto("encrypt_success", ctx, count, cfg.Settings, "")
	}
}

type fieldCryptoResponseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	wroteHeader bool
}

func (w *fieldCryptoResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.wroteHeader = true
}

func (w *fieldCryptoResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *fieldCryptoResponseWriter) Status() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func (w *fieldCryptoResponseWriter) flushRaw() {
	if w.wroteHeader {
		w.ResponseWriter.WriteHeader(w.statusCode)
	}
	_, _ = io.Copy(w.ResponseWriter, w.body)
}

func decryptRequestBody(c *gin.Context, service *fieldcrypto.FieldCryptoService, ctx fieldcrypto.CryptoContext, maxSize int) error {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return fieldcrypto.NewSessionInvalid()
	}
	if len(body) > maxSize {
		return fieldcrypto.NewPayloadTooLarge()
	}
	var payload any
	if len(body) == 0 {
		payload = map[string]any{}
	} else if err := json.Unmarshal(body, &payload); err != nil {
		return &fieldcrypto.FieldCryptoError{SafeCode: "CRYPTO_ERROR", HTTPStatus: http.StatusBadRequest}
	}
	plain, err := service.DecryptJSON(payload, ctx)
	if err != nil {
		return err
	}
	out, err := json.Marshal(plain)
	if err != nil {
		return &fieldcrypto.FieldCryptoError{SafeCode: "CRYPTO_ERROR", HTTPStatus: http.StatusBadRequest}
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(out))
	c.Request.ContentLength = int64(len(out))
	c.Request.Header.Set("Content-Type", "application/json")
	return nil
}

func abortFieldCrypto(c *gin.Context, err error) {
	status, body := fieldcrypto.PublicErrorEnvelope(err)
	c.AbortWithStatusJSON(status, body)
}

func isJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/json")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 12)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}

func logFieldCrypto(event string, ctx fieldcrypto.CryptoContext, count int, settings *fieldcrypto.CryptoSettings, safeCode string) {
	log.Printf("fieldcrypto event=%s endpoint=%s method=%s direction=%s crypto_mode=%s crypto_version=%s values_count=%d safe_error_code=%s",
		event, ctx.Endpoint, ctx.Method, ctx.Direction, settings.Mode, settings.Version, count, safeCode)
}
