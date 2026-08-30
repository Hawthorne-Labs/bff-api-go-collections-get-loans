package fieldcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const nonceLen = 12

func aad(kid string) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s", envelopePrefix, envelopeVersion, kid))
}

// CountScalars counts scalar leaves in a JSON value.
func CountScalars(payload any) int {
	switch v := payload.(type) {
	case map[string]any:
		total := 0
		for _, child := range v {
			total += CountScalars(child)
		}
		return total
	case []any:
		total := 0
		for _, child := range v {
			total += CountScalars(child)
		}
		return total
	default:
		return 1
	}
}

// FieldCryptoService encrypts/decrypts scalar JSON values with AES-256-GCM.
type FieldCryptoService struct {
	keys KeyProvider
}

// NewFieldCryptoService creates a service bound to a key provider.
func NewFieldCryptoService(keys KeyProvider) *FieldCryptoService {
	return &FieldCryptoService{keys: keys}
}

func (s *FieldCryptoService) encryptWithKey(kid string, key, nonce []byte, value any) (string, error) {
	plain, err := EncodeValue(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", NewEncryptionFailed()
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", NewEncryptionFailed()
	}
	sealed := gcm.Seal(nil, nonce, plain, aad(kid))
	if len(sealed) < 16 {
		return "", NewEncryptionFailed()
	}
	env := Envelope{
		KID:        kid,
		Nonce:      nonce,
		Ciphertext: sealed[:len(sealed)-16],
		Tag:        sealed[len(sealed)-16:],
	}
	return env.ToString(), nil
}

func (s *FieldCryptoService) decryptWithKey(env *Envelope, key []byte) (any, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewInvalidTag()
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewInvalidTag()
	}
	plain, err := gcm.Open(nil, env.Nonce, append(env.Ciphertext, env.Tag...), aad(env.KID))
	if err != nil {
		return nil, NewInvalidTag()
	}
	return DecodeValue(plain)
}

// EncryptValue encrypts one scalar value.
func (s *FieldCryptoService) EncryptValue(value any, ctx CryptoContext) (string, error) {
	kid := ctx.KID
	if kid == "" {
		kid = s.keys.ActiveKID()
	}
	key, err := s.keys.KeyFor(kid)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", NewEncryptionFailed()
	}
	return s.encryptWithKey(kid, key, nonce, value)
}

// DecryptValue decrypts one enc:v1 scalar.
func (s *FieldCryptoService) DecryptValue(ciphertext any, ctx CryptoContext) (any, error) {
	env, err := ParseEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := s.keys.KeyFor(env.KID)
	if err != nil {
		return nil, err
	}
	return s.decryptWithKey(env, key)
}

// EncryptJSON recursively encrypts scalar leaves.
func (s *FieldCryptoService) EncryptJSON(payload any, ctx CryptoContext) (any, error) {
	kid := ctx.KID
	if kid == "" {
		kid = s.keys.ActiveKID()
	}
	key, err := s.keys.KeyFor(kid)
	if err != nil {
		return nil, err
	}
	return s.encryptNode(payload, kid, key)
}

func (s *FieldCryptoService) encryptNode(value any, kid string, key []byte) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			encrypted, err := s.encryptNode(child, kid, key)
			if err != nil {
				return nil, err
			}
			out[k] = encrypted
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			encrypted, err := s.encryptNode(child, kid, key)
			if err != nil {
				return nil, err
			}
			out[i] = encrypted
		}
		return out, nil
	default:
		nonce := make([]byte, nonceLen)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, NewEncryptionFailed()
		}
		return s.encryptWithKey(kid, key, nonce, value)
	}
}

// DecryptJSON recursively decrypts scalar leaves; rejects plaintext scalars.
func (s *FieldCryptoService) DecryptJSON(payload any, ctx CryptoContext) (any, error) {
	switch v := payload.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			decrypted, err := s.DecryptJSON(child, ctx)
			if err != nil {
				return nil, err
			}
			out[k] = decrypted
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			decrypted, err := s.DecryptJSON(child, ctx)
			if err != nil {
				return nil, err
			}
			out[i] = decrypted
		}
		return out, nil
	default:
		if !IsEnvelope(payload) {
			return nil, NewPlaintextRejected()
		}
		return s.DecryptValue(payload, ctx)
	}
}
