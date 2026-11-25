package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestFakeProviderAndWebhookSignature(t *testing.T) {
	fake := FakeProvider{}
	session, err := fake.CreateCheckout(context.Background(), CheckoutRequest{TenantID: "tenant", Plan: "pro", SuccessURL: "https://example.test/ok"})
	if err != nil || session.ID == "" {
		t.Fatalf("checkout: %#v %v", session, err)
	}
	payload := []byte(`{"id":"evt_1"}`)
	secret := "whsec-test"
	stamp := time.Now().Unix()
	message := []byte(fmt.Sprintf("%d.%s", stamp, payload))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(message)
	header := fmt.Sprintf("t=%d,v1=%s", stamp, hex.EncodeToString(mac.Sum(nil)))
	if err := VerifyStripeSignature(header, payload, secret, time.Unix(stamp, 0), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStripeSignature(header, []byte("tampered"), secret, time.Unix(stamp, 0), 5*time.Minute); err == nil {
		t.Fatal("tampered webhook accepted")
	}
	if err := VerifyStripeSignature(header, payload, secret, time.Unix(stamp+301, 0), 5*time.Minute); err == nil {
		t.Fatal("stale webhook accepted")
	}
}
