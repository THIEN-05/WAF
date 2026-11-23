package waf

import (
	"html"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const maxTargetBytes = 256 * 1024

var (
	sqlComments = regexp.MustCompile(`(?s)/\*.*?\*/`)
	traversalRE = regexp.MustCompile(`(?:^|/)\.\.(?:/|$)`)
)

type Normalized struct {
	Raw           string
	Decoded       string
	Value         string
	DoubleEncoded bool
	HadNUL        bool
	Traversal     bool
}

// Normalize applies bounded URL decoding, HTML entity decoding, NUL removal,
// path canonicalization, lowercasing, whitespace folding, and SQL comment removal.
func Normalize(input string, isPath bool) Normalized {
	value, _ := normalizeBounded(input, isPath, nil)
	return value
}

func normalizeBounded(input string, isPath bool, expired func() bool) (Normalized, bool) {
	if expired != nil && expired() {
		return Normalized{}, false
	}
	if len(input) > maxTargetBytes {
		input = input[:maxTargetBytes]
	}
	out := Normalized{Raw: input}
	decoded := input
	out.DoubleEncoded = strings.Contains(strings.ToLower(input), "%25")
	for i := 0; i < 3; i++ {
		if expired != nil && expired() {
			return Normalized{}, false
		}
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	if expired != nil && expired() {
		return Normalized{}, false
	}
	decoded = html.UnescapeString(decoded)
	out.HadNUL = strings.ContainsRune(decoded, '\x00')
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	out.Traversal = traversalRE.MatchString(decoded)
	out.Decoded = decoded
	if isPath && decoded != "" {
		if expired != nil && expired() {
			return Normalized{}, false
		}
		wasAbsolute := strings.HasPrefix(decoded, "/")
		decoded = path.Clean(decoded)
		if wasAbsolute && !strings.HasPrefix(decoded, "/") {
			decoded = "/" + decoded
		}
	}
	decoded = strings.ToLower(decoded)
	if expired != nil && expired() {
		return Normalized{}, false
	}
	decoded = sqlComments.ReplaceAllString(decoded, " ")
	out.Value = strings.Join(strings.Fields(decoded), " ")
	return out, true
}
