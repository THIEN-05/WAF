package router

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
)

func punycodeLabel(label string) (string, error) {
	label = strings.ToLower(label)
	runes := []rune(label)
	nonASCII := false
	for _, r := range runes {
		if r > unicode.MaxASCII {
			nonASCII = true
		}
	}
	if !nonASCII {
		return label, nil
	}
	var out strings.Builder
	basic := 0
	for _, r := range runes {
		if r < unicode.MaxASCII {
			if !validBasicRune(r) {
				return "", fmt.Errorf("invalid basic rune")
			}
			out.WriteRune(r)
			basic++
		}
	}
	handled := basic
	if basic > 0 {
		out.WriteByte('-')
	}
	n := int64(punyInitialN)
	delta := int64(0)
	bias := int64(punyInitialBias)
	for handled < len(runes) {
		m := int64(0x10ffff)
		for _, r := range runes {
			v := int64(r)
			if v >= n && v < m {
				m = v
			}
		}
		if m == 0x10ffff {
			return "", fmt.Errorf("invalid punycode input")
		}
		step := (m - n) * int64(handled+1)
		if step < 0 || delta > 1<<62-step {
			return "", fmt.Errorf("punycode overflow")
		}
		delta += step
		n = m
		for _, r := range runes {
			v := int64(r)
			switch {
			case v < n:
				delta++
				if delta < 0 {
					return "", fmt.Errorf("punycode overflow")
				}
			case v == n:
				q := delta
				for k := int64(punyBase); ; k += punyBase {
					t := threshold(k, bias)
					if q < t {
						break
					}
					code := t + (q-t)%(punyBase-t)
					out.WriteByte(encodeDigit(code))
					q = (q - t) / (punyBase - t)
				}
				out.WriteByte(encodeDigit(q))
				bias = adapt(delta, int64(handled+1), handled == basic)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return "xn--" + out.String(), nil
}

func validBasicRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
}
func threshold(k, bias int64) int64 {
	if k <= bias+punyTMin {
		return punyTMin
	}
	if k >= bias+punyTMax {
		return punyTMax
	}
	return k - bias
}
func encodeDigit(d int64) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
func adapt(delta, numPoints int64, first bool) int64 {
	if first {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := int64(0)
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= (punyBase - punyTMin)
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}
