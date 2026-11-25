package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type CheckoutRequest struct{ TenantID, Plan, SuccessURL, CancelURL string }
type Session struct{ ID, URL string }
type PaymentProvider interface {
	CreateCheckout(context.Context, CheckoutRequest) (Session, error)
	CreatePortal(context.Context, string, string) (Session, error)
}

// FakeProvider is deterministic test/dev billing; it never handles payment details.
type FakeProvider struct{}

func (FakeProvider) CreateCheckout(_ context.Context, r CheckoutRequest) (Session, error) {
	if r.TenantID == "" || r.Plan == "" {
		return Session{}, errors.New("tenant and plan are required")
	}
	return Session{ID: "fake_checkout_" + r.TenantID, URL: r.SuccessURL}, nil
}
func (FakeProvider) CreatePortal(_ context.Context, customerID, returnURL string) (Session, error) {
	if customerID == "" {
		return Session{}, errors.New("customer is required")
	}
	return Session{ID: "fake_portal_" + customerID, URL: returnURL}, nil
}

type Event struct {
	ID, Type string
	Created  int64
	Data     []byte
}

// VerifyStripeSignature verifies Stripe's timestamped HMAC-SHA256 envelope before parsing an event.
func VerifyStripeSignature(header string, payload []byte, secret string, now time.Time, tolerance time.Duration) error {
	if secret == "" || tolerance <= 0 {
		return errors.New("webhook verifier is not configured")
	}
	var timestamp string
	var signatures []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		if k == "t" {
			timestamp = v
		}
		if k == "v1" {
			signatures = append(signatures, v)
		}
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || len(signatures) == 0 {
		return errors.New("invalid webhook signature")
	}
	delta := now.Sub(time.Unix(seconds, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		return errors.New("webhook timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	for _, s := range signatures {
		candidate, e := hex.DecodeString(s)
		if e == nil && hmac.Equal(candidate, expected) {
			return nil
		}
	}
	return fmt.Errorf("invalid webhook signature")
}
