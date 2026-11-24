package bot

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const VerificationCookie = "__Host-waf_verified"

var ErrInvalidChallenge = errors.New("invalid challenge")

type KeyRing interface {
	ActiveKeyID() string
	Key(string) ([]byte, bool)
}
type StaticKeyRing struct {
	Active string
	Keys   map[string][]byte
}

func (k StaticKeyRing) ActiveKeyID() string          { return k.Active }
func (k StaticKeyRing) Key(id string) ([]byte, bool) { b, ok := k.Keys[id]; return b, ok }

type challengeTicket struct {
	Kid        string `json:"k"`
	ID         string `json:"i"`
	Site       string `json:"s"`
	UA         string `json:"u"`
	Prefix     string `json:"p"`
	Expires    int64  `json:"e"`
	Difficulty int    `json:"d"`
}
type verifiedCookie struct {
	Kid     string `json:"k"`
	Site    string `json:"s"`
	UA      string `json:"u"`
	Prefix  string `json:"p"`
	Expires int64  `json:"e"`
}
type ChallengeManager struct {
	keysMu  sync.RWMutex
	keys    KeyRing
	mu      sync.Mutex
	used    map[string]time.Time
	maxUsed int
	now     func() time.Time
}

func NewChallengeManager(keys KeyRing) *ChallengeManager {
	return &ChallengeManager{keys: keys, used: map[string]time.Time{}, maxUsed: 100_000, now: time.Now}
}
func (m *ChallengeManager) SetKeyRing(keys KeyRing) {
	if m == nil {
		return
	}
	m.keysMu.Lock()
	m.keys = keys
	m.keysMu.Unlock()
}
func (m *ChallengeManager) keyRing() KeyRing {
	if m == nil {
		return nil
	}
	m.keysMu.RLock()
	defer m.keysMu.RUnlock()
	return m.keys
}
func (m *ChallengeManager) ActiveKeyID() string {
	keys := m.keyRing()
	if keys == nil {
		return ""
	}
	return keys.ActiveKeyID()
}
func (m *ChallengeManager) Issue(site, ua string, ip net.IP, difficulty int, now time.Time) (string, error) {
	keys := m.keyRing()
	if keys == nil {
		return "", ErrInvalidChallenge
	}
	return m.IssueForKey(site, keys.ActiveKeyID(), ua, ip, difficulty, now)
}
func (m *ChallengeManager) IssueForKey(site, keyID, ua string, ip net.IP, difficulty int, now time.Time) (string, error) {
	keys := m.keyRing()
	if keys == nil || site == "" || len(site) > 128 || keyID == "" || len(keyID) > 64 || strings.ContainsAny(keyID, " /\\\t\r\n") || ip == nil || difficulty < 1 || difficulty > 24 {
		return "", ErrInvalidChallenge
	}
	kid := keyID
	key, ok := keys.Key(kid)
	if !ok || len(key) < 32 {
		return "", ErrInvalidChallenge
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", err
	}
	t := challengeTicket{Kid: kid, ID: hex.EncodeToString(idb[:]), Site: site, UA: hashUA(ua), Prefix: ipPrefix(ip), Expires: now.Add(5 * time.Minute).Unix(), Difficulty: difficulty}
	return m.sign(t, key)
}
func (m *ChallengeManager) Verify(ticket, nonce, site, ua string, ip net.IP, now time.Time) (string, error) {
	keys := m.keyRing()
	if keys == nil {
		return "", ErrInvalidChallenge
	}
	return m.VerifyForKey(ticket, nonce, site, ua, ip, keys.ActiveKeyID(), now)
}
func (m *ChallengeManager) VerifyForKey(ticket, nonce, site, ua string, ip net.IP, cookieKeyID string, now time.Time) (string, error) {
	keys := m.keyRing()
	if keys == nil {
		return "", ErrInvalidChallenge
	}
	t, err := m.parseTicket(ticket)
	if err != nil || t.Site != site || t.UA != hashUA(ua) || t.Prefix != ipPrefix(ip) || now.Unix() >= t.Expires || !validPoW(ticket, nonce, t.Difficulty) {
		return "", ErrInvalidChallenge
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, exp := range m.used {
		if !now.Before(exp) {
			delete(m.used, id)
		}
	}
	if _, exists := m.used[t.ID]; exists {
		return "", ErrInvalidChallenge
	}
	if len(m.used) >= m.maxUsed {
		return "", ErrInvalidChallenge
	}
	m.used[t.ID] = time.Unix(t.Expires, 0)
	if cookieKeyID == "" {
		cookieKeyID = keys.ActiveKeyID()
	}
	key, ok := keys.Key(cookieKeyID)
	if !ok || len(key) < 32 {
		return "", ErrInvalidChallenge
	}
	c := verifiedCookie{Kid: cookieKeyID, Site: site, UA: t.UA, Prefix: t.Prefix, Expires: now.Add(30 * time.Minute).Unix()}
	return m.sign(c, key)
}
func (m *ChallengeManager) ValidCookie(value, site, ua string, ip net.IP, now time.Time) bool {
	if m == nil {
		return false
	}
	var c verifiedCookie
	if !m.verify(value, &c) || c.Site != site || c.UA != hashUA(ua) || c.Prefix != ipPrefix(ip) || now.Unix() >= c.Expires {
		return false
	}
	return true
}
func (m *ChallengeManager) parseTicket(value string) (challengeTicket, error) {
	var t challengeTicket
	if !m.verify(value, &t) {
		return t, ErrInvalidChallenge
	}
	keys := m.keyRing()
	if keys == nil {
		return t, ErrInvalidChallenge
	}
	key, ok := keys.Key(t.Kid)
	if !ok {
		return t, ErrInvalidChallenge
	}
	_ = key
	return t, nil
}
func (m *ChallengeManager) verify(value string, out any) bool {
	keys := m.keyRing()
	if keys == nil {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	if json.Unmarshal(raw, out) != nil {
		return false
	}
	var kid string
	switch v := out.(type) {
	case *challengeTicket:
		kid = v.Kid
	case *verifiedCookie:
		kid = v.Kid
	default:
		return false
	}
	key, ok := keys.Key(kid)
	if !ok || len(key) < 32 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return hmac.Equal(sig, mac.Sum(nil))
}
func (m *ChallengeManager) sign(payload any, key []byte) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func hashUA(ua string) string { h := sha256.Sum256([]byte(ua)); return hex.EncodeToString(h[:]) }
func ipPrefix(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return net.IP(v4[:3]).String() + "/24"
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x:%x::/64", v6[0:2], v6[2:4], v6[4:6], v6[6:8])
}
func validPoW(ticket, nonce string, difficulty int) bool {
	if nonce == "" || len(nonce) > 128 {
		return false
	}
	h := sha256.Sum256([]byte(ticket + "." + nonce))
	zero := 0
	for _, b := range h {
		if b == 0 {
			zero += 8
			continue
		}
		for mask := byte(0x80); mask != 0 && b&mask == 0; mask >>= 1 {
			zero++
		}
		break
	}
	return zero >= difficulty
}
func FindNonce(ticket string, difficulty int) string {
	for n := uint64(0); ; n++ {
		nonce := fmt.Sprint(n)
		if validPoW(ticket, nonce, difficulty) {
			return nonce
		}
	}
}

func (m *ChallengeManager) ServeVerify(w http.ResponseWriter, r *http.Request, site string, ip net.IP, ua string) {
	m.ServeVerifyKey(w, r, site, "", ip, ua)
}
func (m *ChallengeManager) ServeVerifyKey(w http.ResponseWriter, r *http.Request, site, keyID string, ip net.IP, ua string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var body struct {
		Token string `json:"token"`
		Nonce string `json:"nonce"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		http.Error(w, "invalid proof", http.StatusBadRequest)
		return
	}
	value, err := m.VerifyForKey(body.Token, body.Nonce, site, ua, ip, keyID, m.now())
	if err != nil {
		http.Error(w, "invalid proof", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: VerificationCookie, Value: value, Path: "/", MaxAge: 1800, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}
func ChallengePage(w http.ResponseWriter, token string) {
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes[:])
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusForbidden)
	encoded, _ := json.Marshal(token)
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Checking browser</title><p>Checking your browser…</p><script nonce="%s">(()=>{const token=%s,difficulty=%d;let n=0;async function run(){while(true){const bytes=new TextEncoder().encode(token+"."+n++),h=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));let z=0;for(const b of h){if(!b){z+=8;continue}for(let m=128;(b&m)===0;m>>=1)z++;break}if(z>=difficulty){await fetch("/__waf/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token,nonce:String(n-1)})});location.reload();return}if(n%%512===0)await new Promise(requestAnimationFrame)}}run()})()</script>`, nonce, encoded, extractDifficulty(token))
}
func extractDifficulty(ticket string) int {
	var t challengeTicket
	if !func() bool {
		parts := strings.Split(ticket, ".")
		if len(parts) != 2 {
			return false
		}
		b, e := base64.RawURLEncoding.DecodeString(parts[0])
		return e == nil && json.Unmarshal(b, &t) == nil
	}() {
		return 0
	}
	return t.Difficulty
}

type CaptchaVerifier interface {
	Verify(context.Context, string, string) bool
}

// TurnstileStub deliberately rejects until a site-scoped verifier is configured.
type TurnstileStub struct{}

func (TurnstileStub) Verify(context.Context, string, string) bool { return false }
