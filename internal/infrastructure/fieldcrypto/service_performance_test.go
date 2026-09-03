package fieldcrypto

import "testing"

type performanceKeyProvider struct {
	key []byte
}

func (p performanceKeyProvider) ActiveKID() string { return "performance-key" }

func (p performanceKeyProvider) KeyFor(string) ([]byte, error) { return p.key, nil }

func BenchmarkEncryptJSON1000Scalars(b *testing.B) {
	service := NewFieldCryptoService(performanceKeyProvider{key: make([]byte, keyLen)})
	payload := make([]any, 1000)
	for i := range payload {
		payload[i] = float64(i)
	}
	ctx := CryptoContext{KID: "performance-key"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := service.EncryptJSON(payload, ctx); err != nil {
			b.Fatal(err)
		}
	}
}
