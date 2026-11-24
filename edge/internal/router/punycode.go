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

func decodePunycodeLabel(label string) (string, error) {
	if !strings.HasPrefix(label, "xn--") {
		return "", fmt.Errorf("not a punycode label")
	}
	input := strings.TrimPrefix(label, "xn--")
	output := make([]rune, 0, len(input))
	if delimiter := strings.LastIndexByte(input, '-'); delimiter >= 0 {
		for _, r := range input[:delimiter] {
			if !validBasicRune(r) {
				return "", fmt.Errorf("invalid basic punycode rune")
			}
			output = append(output, r)
		}
		input = input[delimiter+1:]
	}
	if input == "" {
		return "", fmt.Errorf("empty punycode payload")
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	n, index, bias := int64(punyInitialN), int64(0), int64(punyInitialBias)
	for offset := 0; offset < len(input); {
		oldIndex, weight := index, int64(1)
		for k := int64(punyBase); ; k += punyBase {
			if offset >= len(input) {
				return "", fmt.Errorf("truncated punycode payload")
			}
			digit, ok := decodeDigit(input[offset])
			if !ok || int64(digit) > (maxInt64-index)/weight {
				return "", fmt.Errorf("invalid or overflowing punycode digit")
			}
			offset++
			index += int64(digit) * weight
			threshold := threshold(k, bias)
			if int64(digit) < threshold {
				break
			}
			factor := int64(punyBase) - threshold
			if weight > maxInt64/factor {
				return "", fmt.Errorf("punycode weight overflow")
			}
			weight *= factor
		}
		points := int64(len(output) + 1)
		bias = adapt(index-oldIndex, points, oldIndex == 0)
		increment := index / points
		if increment > 0x10ffff || n > 0x10ffff-increment {
			return "", fmt.Errorf("punycode code point overflow")
		}
		n += increment
		index %= points
		if n >= 0xd800 && n <= 0xdfff {
			return "", fmt.Errorf("punycode surrogate code point")
		}
		if n < 0 || n > 0x10ffff {
			return "", fmt.Errorf("punycode code point out of range")
		}
		output = append(output, 0)
		copy(output[index+1:], output[index:])
		output[index] = rune(n)
		index++
	}
	decoded := string(output)
	for _, r := range decoded {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("disallowed punycode code point")
		}
	}
	return decoded, nil
}

func decodeDigit(b byte) (int, bool) {
	switch {
	case b >= 'a' && b <= 'z':
		return int(b - 'a'), true
	case b >= '0' && b <= '9':
		return int(b-'0') + 26, true
	default:
		return 0, false
	}
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
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	if d < 0 || d >= int64(len(alphabet)) {
		return '?'
	}
	return alphabet[d]
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
