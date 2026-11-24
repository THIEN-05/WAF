package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestArgon2idPasswordEncoding(t *testing.T) {
	hash := hashPassword("Correct horse battery staple")
	if !verifyPassword(hash, "Correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if verifyPassword(hash, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	if verifyPassword("$argon2id$v=19$m=999999999,t=999,p=8$bad$bad", "x") {
		t.Fatal("unbounded parameters accepted")
	}
}

func TestRecoveryCodeShape(t *testing.T) {
	for i := 0; i < 10; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 12 {
			t.Fatalf("recovery code length=%d, want 12", len(code))
		}
		if strings.ToUpper(code) != code {
			t.Fatal("recovery code is not normalized")
		}
	}
}
func TestTOTPAllowsOneStepSkew(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0)
	for _, delta := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := totp.GenerateCodeCustom(secret, now.Add(delta), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatal(err)
		}
		valid, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil || !valid {
			t.Fatalf("TOTP at delta %s rejected", delta)
		}
	}
}
