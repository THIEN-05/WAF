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
	if len(input) > maxTargetBytes {
		input = input[:maxTargetBytes]
	}
	out := Normalized{Raw: input}
	decoded := input
	out.DoubleEncoded = strings.Contains(strings.ToLower(input), "%25")
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	decoded = html.UnescapeString(decoded)
	out.HadNUL = strings.ContainsRune(decoded, '\x00')
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	out.Traversal = traversalRE.MatchString(decoded)
	out.Decoded = decoded
	if isPath && decoded != "" {
		wasAbsolute := strings.HasPrefix(decoded, "/")
		decoded = path.Clean(decoded)
		if wasAbsolute && !strings.HasPrefix(decoded, "/") {
			decoded = "/" + decoded
		}
	}
	decoded = strings.ToLower(decoded)
	decoded = sqlComments.ReplaceAllString(decoded, " ")
	out.Value = strings.Join(strings.Fields(decoded), " ")
	return out
}
