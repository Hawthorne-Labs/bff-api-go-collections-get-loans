package fieldcrypto

// CryptoContext holds per-request crypto metadata safe to log.
type CryptoContext struct {
	KID             string
	RequestID       string
	TraceID         string
	Endpoint        string
	Method          string
	Direction       string
	CryptoRequired  bool
}
