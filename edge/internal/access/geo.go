package access

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type GeoInfo struct {
	Country string
	ASN     uint32
}

type GeoResolver interface {
	Resolve(net.IP) (GeoInfo, error)
}

// MMDBResolver keeps MaxMind databases memory-mapped through maxminddb.Reader.
type MMDBResolver struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
}

func OpenMMDB(countryPath, asnPath string) (*MMDBResolver, error) {
	r := &MMDBResolver{}
	if countryPath == "" && asnPath == "" {
		return nil, fmt.Errorf("at least one MMDB path is required")
	}
	if countryPath != "" {
		reader, err := maxminddb.Open(countryPath)
		if err != nil {
			return nil, fmt.Errorf("open country MMDB: %w", err)
		}
		r.country = reader
	}
	if asnPath != "" {
		reader, err := maxminddb.Open(asnPath)
		if err != nil {
			if closeErr := r.Close(); closeErr != nil {
				return nil, errors.Join(fmt.Errorf("open ASN MMDB: %w", err), fmt.Errorf("close partially opened MMDB: %w", closeErr))
			}
			return nil, fmt.Errorf("open ASN MMDB: %w", err)
		}
		r.asn = reader
	}
	return r, nil
}

func (r *MMDBResolver) Resolve(ip net.IP) (GeoInfo, error) {
	if r == nil || ip == nil {
		return GeoInfo{}, fmt.Errorf("resolver and IP are required")
	}
	var info GeoInfo
	if r.country != nil {
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := r.country.Lookup(ip, &record); err != nil {
			return GeoInfo{}, fmt.Errorf("lookup country: %w", err)
		}
		info.Country = strings.ToUpper(record.Country.ISOCode)
	}
	if r.asn != nil {
		var record struct {
			Number uint32 `maxminddb:"autonomous_system_number"`
		}
		if err := r.asn.Lookup(ip, &record); err != nil {
			return GeoInfo{}, fmt.Errorf("lookup ASN: %w", err)
		}
		info.ASN = record.Number
	}
	return info, nil
}

func (r *MMDBResolver) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	if r.asn != nil && r.asn != r.country {
		if err := r.asn.Close(); err != nil {
			closeErr = fmt.Errorf("close ASN MMDB: %w", err)
		}
	}
	if r.country != nil {
		if err := r.country.Close(); err != nil {
			if closeErr == nil {
				closeErr = fmt.Errorf("close country MMDB: %w", err)
			} else {
				closeErr = fmt.Errorf("%v; close country MMDB: %w", closeErr, err)
			}
		}
	}
	return closeErr
}

type FakeGeoResolver map[string]GeoInfo

func (f FakeGeoResolver) Resolve(ip net.IP) (GeoInfo, error) {
	if ip == nil {
		return GeoInfo{}, fmt.Errorf("IP is required")
	}
	info, ok := f[ip.String()]
	if !ok {
		return GeoInfo{}, fmt.Errorf("no fake GeoIP record for %s", ip)
	}
	return info, nil
}
