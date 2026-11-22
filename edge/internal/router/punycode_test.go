package router

import "testing"

func TestEncodeDigitAllValuesAndBounds(t *testing.T) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := int64(0); i < int64(len(alphabet)); i++ {
		if got := encodeDigit(i); got != alphabet[i] {
			t.Errorf("encodeDigit(%d)=%q want %q", i, got, alphabet[i])
		}
	}
	for _, value := range []int64{-1, int64(len(alphabet)), 1 << 40} {
		if got := encodeDigit(value); got != '?' {
			t.Errorf("encodeDigit(%d)=%q want invalid sentinel", value, got)
		}
	}
}
