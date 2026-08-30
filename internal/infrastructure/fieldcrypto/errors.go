package fieldcrypto

import "net/http"

// FieldCryptoError is the base error type. SafeCode is the only detail exposed to clients.
type FieldCryptoError struct {
	SafeCode   string
	HTTPStatus int
}

func (e *FieldCryptoError) Error() string {
	return e.SafeCode
}

func newFieldCryptoError(safeCode string, httpStatus int) *FieldCryptoError {
	return &FieldCryptoError{SafeCode: safeCode, HTTPStatus: httpStatus}
}

// InvalidEnvelope indicates malformed enc:v1 envelope.
type InvalidEnvelope struct{ FieldCryptoError }

func NewInvalidEnvelope() *InvalidEnvelope {
	return &InvalidEnvelope{*newFieldCryptoError("CRYPTO_INVALID_FORMAT", http.StatusBadRequest)}
}

// UnsupportedVersion indicates unsupported enc version.
type UnsupportedVersion struct{ FieldCryptoError }

func NewUnsupportedVersion() *UnsupportedVersion {
	return &UnsupportedVersion{*newFieldCryptoError("CRYPTO_UNSUPPORTED_VERSION", http.StatusBadRequest)}
}

// UnknownKid indicates unknown key id.
type UnknownKid struct{ FieldCryptoError }

func NewUnknownKid() *UnknownKid {
	return &UnknownKid{*newFieldCryptoError("CRYPTO_UNKNOWN_KID", http.StatusBadRequest)}
}

// InvalidTag indicates AEAD tag verification failure.
type InvalidTag struct{ FieldCryptoError }

func NewInvalidTag() *InvalidTag {
	return &InvalidTag{*newFieldCryptoError("CRYPTO_INVALID_TAG", http.StatusBadRequest)}
}

// PlaintextRejected indicates cleartext on a protected request.
type PlaintextRejected struct{ FieldCryptoError }

func NewPlaintextRejected() *PlaintextRejected {
	return &PlaintextRejected{*newFieldCryptoError("CRYPTO_PLAINTEXT_REJECTED", http.StatusBadRequest)}
}

// UnsupportedType indicates unsupported scalar type for valuecodec.
type UnsupportedType struct{ FieldCryptoError }

func NewUnsupportedType() *UnsupportedType {
	return &UnsupportedType{*newFieldCryptoError("CRYPTO_UNSUPPORTED_TYPE", http.StatusBadRequest)}
}

// PayloadTooLarge indicates encrypted payload exceeds limit.
type PayloadTooLarge struct{ FieldCryptoError }

func NewPayloadTooLarge() *PayloadTooLarge {
	return &PayloadTooLarge{*newFieldCryptoError("CRYPTO_PAYLOAD_TOO_LARGE", http.StatusRequestEntityTooLarge)}
}

// EncryptionFailed indicates response encryption failure.
type EncryptionFailed struct{ FieldCryptoError }

func NewEncryptionFailed() *EncryptionFailed {
	return &EncryptionFailed{*newFieldCryptoError("CRYPTO_RESPONSE_ENCRYPTION_FAILED", http.StatusInternalServerError)}
}

// SessionInvalid indicates missing/invalid/expired crypto session.
type SessionInvalid struct{ FieldCryptoError }

func NewSessionInvalid() *SessionInvalid {
	return &SessionInvalid{*newFieldCryptoError("CRYPTO_SESSION_INVALID", http.StatusUnauthorized)}
}

// SessionStoreUnavailable indicates crypto session store dependency down.
type SessionStoreUnavailable struct{ FieldCryptoError }

func NewSessionStoreUnavailable() *SessionStoreUnavailable {
	return &SessionStoreUnavailable{*newFieldCryptoError("SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)}
}

// TenantAuthorityUnavailable indicates Core management unavailable during handshake.
type TenantAuthorityUnavailable struct{ FieldCryptoError }

func NewTenantAuthorityUnavailable() *TenantAuthorityUnavailable {
	return &TenantAuthorityUnavailable{*newFieldCryptoError("SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)}
}

func asFieldCryptoError(err error) *FieldCryptoError {
	switch e := err.(type) {
	case *InvalidEnvelope:
		return &e.FieldCryptoError
	case *UnsupportedVersion:
		return &e.FieldCryptoError
	case *UnknownKid:
		return &e.FieldCryptoError
	case *InvalidTag:
		return &e.FieldCryptoError
	case *PlaintextRejected:
		return &e.FieldCryptoError
	case *UnsupportedType:
		return &e.FieldCryptoError
	case *PayloadTooLarge:
		return &e.FieldCryptoError
	case *EncryptionFailed:
		return &e.FieldCryptoError
	case *SessionInvalid:
		return &e.FieldCryptoError
	case *SessionStoreUnavailable:
		return &e.FieldCryptoError
	case *TenantAuthorityUnavailable:
		return &e.FieldCryptoError
	case *FieldCryptoError:
		return e
	default:
		return newFieldCryptoError("CRYPTO_ERROR", http.StatusBadRequest)
	}
}
