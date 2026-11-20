package access

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type prefixNode struct {
	children [2]*prefixNode
	terminal bool
}

// PrefixTree is an immutable-after-build IPv4/IPv6 radix tree.
type PrefixTree struct {
	v4 *prefixNode
	v6 *prefixNode
}

func NewPrefixTree(prefixes []string) (*PrefixTree, error) {
	t := &PrefixTree{v4: &prefixNode{}, v6: &prefixNode{}}
	for _, raw := range prefixes {
		if err := t.Insert(raw); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *PrefixTree) Insert(raw string) error {
	if t == nil {
		return fmt.Errorf("prefix tree is nil")
	}
	if t.v4 == nil {
		t.v4 = &prefixNode{}
	}
	if t.v6 == nil {
		t.v6 = &prefixNode{}
	}
	raw = strings.TrimSpace(raw)
	var prefix netip.Prefix
	var err error
	if strings.Contains(raw, "/") {
		prefix, err = netip.ParsePrefix(raw)
	} else {
		var addr netip.Addr
		addr, err = netip.ParseAddr(raw)
		if err == nil {
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
	}
	if err != nil {
		return fmt.Errorf("invalid IP prefix %q: %w", raw, err)
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return fmt.Errorf("invalid IPv4-mapped prefix %q", raw)
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	prefix = prefix.Masked()
	root := t.v6
	if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		root = t.v4
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
	}
	n := root
	for bit := 0; bit < prefix.Bits(); bit++ {
		branch := addressBit(prefix.Addr(), bit)
		if n.children[branch] == nil {
			n.children[branch] = &prefixNode{}
		}
		n = n.children[branch]
	}
	n.terminal = true
	return nil
}

func (t *PrefixTree) Contains(ip net.IP) bool {
	if t == nil || ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	root := t.v6
	if addr.Is4() {
		root = t.v4
	}
	n := root
	if n == nil {
		return false
	}
	if n.terminal {
		return true
	}
	for bit := 0; bit < addr.BitLen(); bit++ {
		n = n.children[addressBit(addr, bit)]
		if n == nil {
			return false
		}
		if n.terminal {
			return true
		}
	}
	return false
}

func addressBit(addr netip.Addr, bit int) int {
	if addr.Is4() {
		bytes := addr.As4()
		return int((bytes[bit/8] >> (7 - bit%8)) & 1)
	}
	bytes := addr.As16()
	return int((bytes[bit/8] >> (7 - bit%8)) & 1)
}
