package fieldcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"reflect"
	"testing"
)

func TestEncryptJSONBuildsAEADOnceAndUsesUniqueNonces(t *testing.T) {
	service := NewFieldCryptoService(performanceKeyProvider{key: make([]byte, keyLen)})
	builds := 0
	service.newAEAD = func(key []byte) (cipher.AEAD, error) {
		builds++
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	payload := []any{"first", float64(2), true, nil}
	ctx := CryptoContext{KID: "performance-key"}

	sealed, err := service.EncryptJSON(payload, ctx)
	if err != nil {
		t.Fatalf("encrypt json: %v", err)
	}
	if builds != 1 {
		t.Fatalf("AEAD builds=%d want 1", builds)
	}

	nonces := make(map[string]struct{}, len(payload))
	for _, value := range sealed.([]any) {
		envelope, err := ParseEnvelope(value)
		if err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		nonce := string(envelope.Nonce)
		if _, exists := nonces[nonce]; exists {
			t.Fatal("nonce reused within one encrypted response")
		}
		nonces[nonce] = struct{}{}
	}

	restored, err := service.DecryptJSON(sealed, ctx)
	if err != nil {
		t.Fatalf("decrypt json: %v", err)
	}
	if !reflect.DeepEqual(restored, payload) {
		t.Fatalf("roundtrip=%#v want %#v", restored, payload)
	}
}
