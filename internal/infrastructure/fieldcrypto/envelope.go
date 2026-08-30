package fieldcrypto

import (
	"encoding/base64"
	"strings"
)

const (
	envelopePrefix  = "enc"
	envelopeVersion = "v1"
	envelopeSegments = 6
)

// Envelope holds parsed enc:v1 segments.
type Envelope struct {
	KID        string
	Nonce      []byte
	Ciphertext []byte
	Tag        []byte
}

func b64URLEncode(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func b64URLDecode(text string) ([]byte, error) {
	if text == "" {
		return nil, NewInvalidEnvelope()
	}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, NewInvalidEnvelope()
	}
	return raw, nil
}

// ToString formats enc:v1:<kid>:<nonce>:<ciphertext>:<tag>.
func (e Envelope) ToString() string {
	return strings.Join([]string{
		envelopePrefix,
		envelopeVersion,
		e.KID,
		b64URLEncode(e.Nonce),
		b64URLEncode(e.Ciphertext),
		b64URLEncode(e.Tag),
	}, ":")
}

// IsEnvelope reports whether value is an enc:v1 string.
func IsEnvelope(value any) bool {
	s, ok := value.(string)
	return ok && strings.HasPrefix(s, envelopePrefix+":"+envelopeVersion+":")
}

// ParseEnvelope parses enc:v1:<kid>:<nonce>:<ciphertext>:<tag>.
func ParseEnvelope(value any) (*Envelope, error) {
	s, ok := value.(string)
	if !ok {
		return nil, NewInvalidEnvelope()
	}
	if strings.ContainsAny(s, "\n\r") {
		return nil, NewInvalidEnvelope()
	}
	parts := strings.Split(s, ":")
	if len(parts) != envelopeSegments || parts[0] != envelopePrefix {
		return nil, NewInvalidEnvelope()
	}
	if parts[1] != envelopeVersion {
		return nil, NewUnsupportedVersion()
	}
	kid := parts[2]
	if kid == "" {
		return nil, NewInvalidEnvelope()
	}
	nonce, err := b64URLDecode(parts[3])
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64URLDecode(parts[4])
	if err != nil {
		return nil, err
	}
	tag, err := b64URLDecode(parts[5])
	if err != nil {
		return nil, err
	}
	if len(nonce) != 12 || len(tag) != 16 || len(ciphertext) == 0 {
		return nil, NewInvalidEnvelope()
	}
	return &Envelope{
		KID:        kid,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Tag:        tag,
	}, nil
}
