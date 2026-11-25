package kmsca

import "net"

// allIPRanges is every IPv4 and IPv6 address, for excluding IP SANs entirely.
func allIPRanges() []*net.IPNet {
	return []*net.IPNet{
		{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	}
}
