package fieldcrypto

// Public error codes 90100-90109 matching Python public_error_code().
var publicErrorCodes = map[string]int{
	"CRYPTO_ERROR":                        90100,
	"CRYPTO_INVALID_FORMAT":               90101,
	"CRYPTO_UNSUPPORTED_VERSION":          90102,
	"CRYPTO_UNKNOWN_KID":                  90103,
	"CRYPTO_INVALID_TAG":                  90104,
	"CRYPTO_PLAINTEXT_REJECTED":           90105,
	"CRYPTO_UNSUPPORTED_TYPE":             90106,
	"CRYPTO_PAYLOAD_TOO_LARGE":            90107,
	"CRYPTO_RESPONSE_ENCRYPTION_FAILED":   90108,
	"CRYPTO_SESSION_INVALID":              90109,
	"SERVICE_UNAVAILABLE":                 90011,
}

var publicErrorMessages = map[int]string{
	90100: "No se pudo procesar la solicitud cifrada.",
	90101: "Formato de cifrado invalido.",
	90102: "Version de cifrado no soportada.",
	90103: "Llave de cifrado no reconocida.",
	90104: "No se pudo validar la integridad de la solicitud cifrada.",
	90105: "La solicitud debe enviarse cifrada.",
	90106: "Tipo de dato cifrado no soportado.",
	90107: "La solicitud cifrada supera el tamano permitido.",
	90108: "No se pudo proteger la respuesta.",
	90109: "Sesion de cifrado invalida.",
	90011: "Servicio no disponible.",
	90018: "No se pudo procesar la solicitud.",
}

// PublicErrorCode maps a safe code to the numeric public code.
func PublicErrorCode(code string) int {
	if n, ok := publicErrorCodes[code]; ok {
		return n
	}
	return 90018
}

// CatalogErrorMessage returns the Spanish public message for a public code.
func CatalogErrorMessage(publicCode int) string {
	if msg, ok := publicErrorMessages[publicCode]; ok {
		return msg
	}
	return publicErrorMessages[90018]
}

// PublicErrorEnvelope builds the JSON error envelope for crypto failures.
func PublicErrorEnvelope(err error) (status int, body map[string]any) {
	fc := asFieldCryptoError(err)
	publicCode := PublicErrorCode(fc.SafeCode)
	return fc.HTTPStatus, map[string]any{
		"error": map[string]any{
			"code":    publicCode,
			"message": CatalogErrorMessage(publicCode),
		},
	}
}
