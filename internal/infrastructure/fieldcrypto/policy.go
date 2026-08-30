package fieldcrypto

import (
	"regexp"
	"strings"
)

// CryptoRule describes decrypt/encrypt requirements for one endpoint.
type CryptoRule struct {
	Method          string
	Path            string
	DecryptRequest  bool
	EncryptResponse bool
	matcher         *regexp.Regexp
}

// Matches reports whether method+path satisfy this rule.
func (r *CryptoRule) Matches(method, path string) bool {
	return strings.EqualFold(method, r.Method) && r.matcher.MatchString(path)
}

func compilePathPattern(path string) *regexp.Regexp {
	tokenRe := regexp.MustCompile(`(\{[^/}]+\})`)
	var pattern strings.Builder
	pattern.WriteString("^")
	remaining := path
	for {
		loc := tokenRe.FindStringIndex(remaining)
		if loc == nil {
			pattern.WriteString(regexp.QuoteMeta(remaining))
			break
		}
		pattern.WriteString(regexp.QuoteMeta(remaining[:loc[0]]))
		pattern.WriteString("[^/]+")
		remaining = remaining[loc[1]:]
	}
	pattern.WriteString("$")
	return regexp.MustCompile(pattern.String())
}

// CryptoPolicy resolves endpoint crypto rules.
type CryptoPolicy struct {
	rules []CryptoRule
}

// NewCryptoPolicy creates a policy from rules.
func NewCryptoPolicy(rules []CryptoRule) *CryptoPolicy {
	return &CryptoPolicy{rules: rules}
}

// FromEntries builds rules from tuples (method, path, decryptRequest, encryptResponse).
func FromEntries(entries [][4]any) *CryptoPolicy {
	rules := make([]CryptoRule, 0, len(entries))
	for _, entry := range entries {
		method := strings.ToUpper(entry[0].(string))
		path := entry[1].(string)
		decrypt := entry[2].(bool)
		encrypt := entry[3].(bool)
		rules = append(rules, CryptoRule{
			Method:          method,
			Path:            path,
			DecryptRequest:  decrypt,
			EncryptResponse: encrypt,
			matcher:         compilePathPattern(path),
		})
	}
	return NewCryptoPolicy(rules)
}

// Resolve returns the first matching rule or nil.
func (p *CryptoPolicy) Resolve(method, path string) *CryptoRule {
	for i := range p.rules {
		if p.rules[i].Matches(method, path) {
			return &p.rules[i]
		}
	}
	return nil
}
