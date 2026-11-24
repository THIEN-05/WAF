package listener

import (
	"crypto/md5" //nolint:gosec // JA3 protocol compatibility uses MD5 only as a non-security fingerprint.
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

const maxClientHelloBytes = 16 << 10

// helloCaptureConn observes the bytes TLS reads without consuming or delaying them.
type helloCaptureConn struct {
	net.Conn
	mu              sync.Mutex
	buf             []byte
	fingerprintOnce sync.Once
	ja3, ja4        string
}

func (c *helloCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		remaining := maxClientHelloBytes - len(c.buf)
		if remaining > 0 {
			copyN := n
			if copyN > remaining {
				copyN = remaining
			}
			c.buf = append(c.buf, p[:copyN]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *helloCaptureConn) Fingerprint() (string, string) {
	c.fingerprintOnce.Do(func() {
		c.mu.Lock()
		b := append([]byte(nil), c.buf...)
		c.mu.Unlock()
		c.ja3, c.ja4, _ = fingerprintClientHello(b)
	})
	return c.ja3, c.ja4
}

type helloCaptureListener struct{ net.Listener }

func (l helloCaptureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloCaptureConn{Conn: c}, nil
}

func fingerprintClientHello(record []byte) (string, string, error) {
	// Parse only a single TLS record containing a complete ClientHello. A fragmented
	// or oversized hello is intentionally left without a fingerprint.
	if len(record) < 9 || record[0] != 22 {
		return "", "", fmt.Errorf("not a TLS handshake record")
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen > maxClientHelloBytes-5 || len(record) < 5+recordLen {
		return "", "", fmt.Errorf("incomplete TLS record")
	}
	b := record[5 : 5+recordLen]
	if len(b) < 4 || b[0] != 1 {
		return "", "", fmt.Errorf("not a ClientHello")
	}
	hlen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if hlen+4 > len(b) || hlen < 2+32+1 {
		return "", "", fmt.Errorf("incomplete ClientHello")
	}
	p := 4
	legacyVersion := u16(b[p:])
	p += 2
	p += 32
	sidLen := int(b[p])
	p++
	if p+sidLen+2 > len(b) {
		return "", "", fmt.Errorf("invalid session id")
	}
	p += sidLen
	cipherLen := int(u16(b[p:]))
	p += 2
	if cipherLen%2 != 0 || p+cipherLen+1 > len(b) {
		return "", "", fmt.Errorf("invalid cipher suites")
	}
	ciphers := values(b[p : p+cipherLen])
	p += cipherLen
	compLen := int(b[p])
	p++
	if p+compLen > len(b) {
		return "", "", fmt.Errorf("invalid compression methods")
	}
	p += compLen
	extensions, groups, points, sigalgs, alpns := []uint16{}, []uint16{}, []uint8{}, []uint16{}, []string{}
	version := legacyVersion
	sni := false
	if p < 4+hlen {
		if p+2 > len(b) {
			return "", "", fmt.Errorf("invalid extension length")
		}
		extLen := int(u16(b[p:]))
		p += 2
		if p+extLen > 4+hlen {
			return "", "", fmt.Errorf("truncated extensions")
		}
		end := p + extLen
		for p < end {
			if p+4 > end {
				return "", "", fmt.Errorf("truncated extension")
			}
			typ, n := u16(b[p:]), int(u16(b[p+2:]))
			p += 4
			if p+n > end {
				return "", "", fmt.Errorf("invalid extension body")
			}
			d := b[p : p+n]
			p += n
			if !isGREASE(typ) {
				extensions = append(extensions, typ)
			}
			switch typ {
			case 0:
				sni = true
			case 10:
				if len(d) >= 2 {
					l := int(u16(d))
					if l%2 == 0 && l+2 <= len(d) {
						groups = values(d[2 : 2+l])
					}
				}
			case 11:
				if len(d) >= 1 && int(d[0])+1 <= len(d) {
					points = append(points, d[1:1+int(d[0])]...)
				}
			case 13:
				if len(d) >= 2 {
					l := int(u16(d))
					if l%2 == 0 && l+2 <= len(d) {
						sigalgs = values(d[2 : 2+l])
					}
				}
			case 16:
				if len(d) >= 3 {
					q := 2
					for q < len(d) {
						l := int(d[q])
						q++
						if q+l > len(d) {
							break
						}
						alpns = append(alpns, string(d[q:q+l]))
						q += l
					}
				}
			case 43:
				if len(d) >= 3 {
					l := int(d[0])
					if l%2 == 0 && l+1 <= len(d) {
						vs := values(d[1 : 1+l])
						for _, v := range vs {
							if v > version && !isGREASE(v) {
								version = v
							}
						}
					}
				}
			}
		}
	}
	filteredCiphers := filterGREASE(ciphers)
	ja3Raw := strings.Join([]string{fmt.Sprint(legacyVersion), joinU16(filteredCiphers), joinU16(extensions), joinU16(groups), joinU8(points)}, ",")
	//nolint:gosec // JA3 requires MD5 for compatibility; this is not used for security/authentication. TestClientHelloFingerprintsRepresentativeProfiles checks the golden digest.
	md := md5.Sum([]byte(ja3Raw))
	ja3 := hex.EncodeToString(md[:])
	ja4 := makeJA4(version, sni, filteredCiphers, extensions, sigalgs, alpns)
	return ja3, ja4, nil
}

func u16(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }
func values(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := u16(b[i:])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>12 == (v>>4)&0x0f }
func filterGREASE(in []uint16) []uint16 {
	out := in[:0]
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
func joinU16(v []uint16) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, "-")
}
func joinU8(v []uint8) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, "-")
}
func makeJA4(version uint16, sni bool, ciphers, exts, sig []uint16, alpn []string) string {
	v := "00"
	switch version {
	case 0x0304:
		v = "13"
	case 0x0303:
		v = "12"
	case 0x0302:
		v = "11"
	case 0x0301:
		v = "10"
	}
	name := "i"
	if sni {
		name = "d"
	}
	a := "00"
	if len(alpn) > 0 && len(alpn[0]) > 0 {
		first, last := alpn[0][0], alpn[0][len(alpn[0])-1]
		if !isASCIIAlnum(first) {
			a = hex.EncodeToString([]byte{first})[0:1]
		}
		if !isASCIIAlnum(last) {
			a = a[:1] + hex.EncodeToString([]byte{last})[1:]
		}
		if isASCIIAlnum(first) {
			a = string(first)
		}
		if isASCIIAlnum(last) {
			a = a[:1] + string(last)
		}
	}
	count := func(n int) string {
		if n > 99 {
			n = 99
		}
		return fmt.Sprintf("%02d", n)
	}
	c := make([]uint16, len(ciphers))
	copy(c, ciphers)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	e := make([]uint16, 0, len(exts))
	for _, ext := range exts {
		if ext != 0 && ext != 16 {
			e = append(e, ext)
		}
	}
	sort.Slice(e, func(i, j int) bool { return e[i] < e[j] })
	ch, eh := "000000000000", "000000000000"
	if len(c) > 0 {
		cs := sha256.Sum256([]byte(joinHex(c)))
		ch = hex.EncodeToString(cs[:])[:12]
	}
	if len(e) > 0 || len(sig) > 0 {
		material := joinHex(e)
		if len(sig) > 0 {
			material += "_" + joinHex(sig)
		}
		ex := sha256.Sum256([]byte(material))
		eh = hex.EncodeToString(ex[:])[:12]
	}
	return "t" + v + name + count(len(ciphers)) + count(len(exts)) + a + "_" + ch + "_" + eh
}
func joinHex(v []uint16) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprintf("%04x", n)
	}
	return strings.Join(s, ",")
}
func isASCIIAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}
