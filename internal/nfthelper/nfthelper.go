// Package nfthelper provides ergonomic helper functions for building nftables
// expression lists ([]expr.Any). Each function generates the netlink VM
// expression sequence that the kernel expects for a particular matching or
// action operation, following the pallium architecture pattern of composable
// expression builders.
//
// Functions are grouped by purpose:
//   - Protocol matchers: IP source/dest, TCP/UDP ports, ICMP types, L4 proto
//   - Meta matchers: interface names, marks, nfproto
//   - CT matchers: connection-tracking state, ct marks
//   - Verdicts: accept, drop, return, jump, goto
//   - Actions: counter, log, limit, reject, NAT, masquerade, notrack, flow offload
//   - Combiner: concatenate expression slices into a single rule
//
// Usage example:
//
//	rule := nfthelper.Combine(
//	    nfthelper.MatchIifname("eth0"),
//	    nfthelper.MatchIPProtocol("tcp"),
//	    nfthelper.MatchTCPDport(443),
//	    nfthelper.MatchCTState("new"),
//	    nfthelper.Counter(),
//	    nfthelper.Accept(),
//	)
package nfthelper

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// Combiner
// ---------------------------------------------------------------------------

// Combine concatenates multiple expression slices into a single []expr.Any
// suitable for passing as a rule's expression list. This is the primary way
// to compose matchers and actions produced by the other functions in this
// package.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchIPSaddr("10.0.0.0/8"),
//	    nfthelper.MatchTCPDport(80),
//	    nfthelper.Accept(),
//	)
func Combine(parts ...[]expr.Any) []expr.Any {
	var result []expr.Any
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}

// ---------------------------------------------------------------------------
// Protocol matchers — IPv4
// ---------------------------------------------------------------------------

// MatchIPSaddr returns expressions that match the IPv4 source address field.
// The addr parameter may be a single IP ("192.168.1.1") or a CIDR prefix
// ("10.0.0.0/8"). For a single IP, an exact comparison is generated. For a
// CIDR, a payload + bitwise (mask) + cmp sequence is generated.
//
// Example:
//
//	// Match packets from 10.0.0.0/8
//	exprs := nfthelper.MatchIPSaddr("10.0.0.0/8")
//
//	// Match packets from exactly 192.168.1.1
//	exprs := nfthelper.MatchIPSaddr("192.168.1.1")
func MatchIPSaddr(addr string) []expr.Any {
	return matchIPv4Field(12, addr) // IPv4 header offset 12 = source address
}

// MatchIPDaddr returns expressions that match the IPv4 destination address
// field. The addr parameter may be a single IP or a CIDR prefix.
//
// Example:
//
//	exprs := nfthelper.MatchIPDaddr("192.168.0.0/16")
func MatchIPDaddr(addr string) []expr.Any {
	return matchIPv4Field(16, addr) // IPv4 header offset 16 = destination address
}

// matchIPv4Field generates a payload load from the network header at the given
// offset (4 bytes for IPv4 addresses), optionally followed by a bitwise mask
// for CIDR matching, and a cmp for equality.
func matchIPv4Field(offset uint32, addr string) []expr.Any {
	// Try CIDR first.
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			// Fall through to single IP parse as a best effort.
			return matchIPv4Exact(offset, addr)
		}
		ip := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()
		if ip == nil || mask == nil {
			return nil
		}
		return []expr.Any{
			// Load 4 bytes from network header at offset into register 1.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          4,
			},
			// Bitwise AND with the netmask: reg1 = (reg1 & mask) ^ 0.
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte(mask),
				Xor:            []byte{0, 0, 0, 0},
			},
			// Compare register 1 with the masked network address.
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ip),
			},
		}
	}
	return matchIPv4Exact(offset, addr)
}

func matchIPv4Exact(offset uint32, addr string) []expr.Any {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(ip4),
		},
	}
}

// ---------------------------------------------------------------------------
// Protocol matchers — IPv6
// ---------------------------------------------------------------------------

// MatchIP6Saddr returns expressions that match the IPv6 source address field.
// The addr parameter may be a single IPv6 address ("2001:db8::1") or a CIDR
// prefix ("2001:db8::/32").
//
// Example:
//
//	exprs := nfthelper.MatchIP6Saddr("fd00::/8")
func MatchIP6Saddr(addr string) []expr.Any {
	return matchIPv6Field(8, addr) // IPv6 header offset 8 = source address
}

// MatchIP6Daddr returns expressions that match the IPv6 destination address
// field. The addr parameter may be a single IPv6 address or a CIDR prefix.
//
// Example:
//
//	exprs := nfthelper.MatchIP6Daddr("2001:db8::1")
func MatchIP6Daddr(addr string) []expr.Any {
	return matchIPv6Field(24, addr) // IPv6 header offset 24 = destination address
}

func matchIPv6Field(offset uint32, addr string) []expr.Any {
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return matchIPv6Exact(offset, addr)
		}
		ip := ipNet.IP.To16()
		mask := make([]byte, 16)
		copy(mask, ipNet.Mask)
		if ip == nil {
			return nil
		}
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          16,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            16,
				Mask:           mask,
				Xor:            make([]byte, 16),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(ip),
			},
		}
	}
	return matchIPv6Exact(offset, addr)
}

func matchIPv6Exact(offset uint32, addr string) []expr.Any {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          16,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(ip6),
		},
	}
}

// ---------------------------------------------------------------------------
// Protocol matchers — TCP ports
// ---------------------------------------------------------------------------

// MatchTCPDport returns expressions that match the TCP destination port.
// The port is encoded in network byte order (big-endian). This loads 2 bytes
// from transport header offset 2 (the destination port field in the TCP
// header).
//
// Example:
//
//	exprs := nfthelper.MatchTCPDport(443)
func MatchTCPDport(port uint16) []expr.Any {
	return matchTransportPort(2, port) // TCP dest port offset = 2
}

// MatchTCPSport returns expressions that match the TCP source port.
//
// Example:
//
//	exprs := nfthelper.MatchTCPSport(12345)
func MatchTCPSport(port uint16) []expr.Any {
	return matchTransportPort(0, port) // TCP source port offset = 0
}

// ---------------------------------------------------------------------------
// Protocol matchers — UDP ports
// ---------------------------------------------------------------------------

// MatchUDPDport returns expressions that match the UDP destination port.
//
// Example:
//
//	exprs := nfthelper.MatchUDPDport(53)
func MatchUDPDport(port uint16) []expr.Any {
	return matchTransportPort(2, port) // UDP dest port offset = 2
}

// MatchUDPSport returns expressions that match the UDP source port.
//
// Example:
//
//	exprs := nfthelper.MatchUDPSport(1024)
func MatchUDPSport(port uint16) []expr.Any {
	return matchTransportPort(0, port) // UDP source port offset = 0
}

// matchTransportPort loads a 2-byte field from the transport header at the
// specified offset and compares it (big-endian) to the given port number.
func matchTransportPort(offset uint32, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       offset,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
	}
}

// ---------------------------------------------------------------------------
// Protocol matchers — ICMP
// ---------------------------------------------------------------------------

// icmpTypes maps human-readable ICMP type names to their numeric values.
var icmpTypes = map[string]byte{
	"echo-reply":               0,
	"destination-unreachable":  3,
	"source-quench":            4,
	"redirect":                 5,
	"echo-request":             8,
	"router-advertisement":     9,
	"router-solicitation":      10,
	"time-exceeded":            11,
	"parameter-problem":        12,
	"timestamp-request":        13,
	"timestamp-reply":          14,
	"info-request":             15,
	"info-reply":               16,
	"address-mask-request":     17,
	"address-mask-reply":       18,
}

// MatchICMPType returns expressions that match an ICMPv4 type field by name.
// Supported names include "echo-request", "echo-reply",
// "destination-unreachable", "redirect", "time-exceeded", and others.
// The expressions load 1 byte from transport header offset 0 (the ICMP type
// field) and compare it.
//
// Example:
//
//	exprs := nfthelper.MatchICMPType("echo-request")
func MatchICMPType(typeName string) []expr.Any {
	code, ok := icmpTypes[typeName]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// icmpv6Types maps human-readable ICMPv6 type names to their numeric values.
var icmpv6Types = map[string]byte{
	"destination-unreachable": 1,
	"packet-too-big":          2,
	"time-exceeded":           3,
	"parameter-problem":       4,
	"echo-request":            128,
	"echo-reply":              129,
	"mld-listener-query":      130,
	"mld-listener-report":     131,
	"mld-listener-done":       132,
	"router-solicitation":     133,
	"router-advertisement":    134,
	"nd-neighbor-solicit":     135,
	"nd-neighbor-advert":      136,
	"nd-redirect":             137,
	"mld2-listener-report":    143,
}

// MatchICMPv6Type returns expressions that match an ICMPv6 type field by name.
// Supported names include "echo-request", "echo-reply",
// "nd-neighbor-solicit", "nd-neighbor-advert", "router-solicitation",
// "router-advertisement", and others.
//
// Example:
//
//	exprs := nfthelper.MatchICMPv6Type("nd-neighbor-solicit")
func MatchICMPv6Type(typeName string) []expr.Any {
	code, ok := icmpv6Types[typeName]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// ---------------------------------------------------------------------------
// Protocol matchers — IP protocol / L4 protocol
// ---------------------------------------------------------------------------

// ipProtocols maps protocol names to their IP protocol numbers.
var ipProtocols = map[string]byte{
	"tcp":    unix.IPPROTO_TCP,
	"udp":    unix.IPPROTO_UDP,
	"icmp":   unix.IPPROTO_ICMP,
	"icmpv6": unix.IPPROTO_ICMPV6,
	"sctp":   unix.IPPROTO_SCTP,
	"gre":    unix.IPPROTO_GRE,
	"esp":    unix.IPPROTO_ESP,
	"ah":     unix.IPPROTO_AH,
	"udplite": unix.IPPROTO_UDPLITE,
}

// MatchIPProtocol returns expressions that match the IPv4 header protocol
// field (1 byte at network header offset 9). The proto parameter is a
// human-readable name such as "tcp", "udp", "icmp", "icmpv6", "sctp",
// "gre", "esp", "ah", or "udplite".
//
// Example:
//
//	exprs := nfthelper.MatchIPProtocol("tcp")
func MatchIPProtocol(proto string) []expr.Any {
	p, ok := ipProtocols[strings.ToLower(proto)]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       9, // IPv4 protocol field offset
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{p},
		},
	}
}

// MatchL4Proto returns expressions that match the layer-4 protocol using the
// meta l4proto key. This works for both IPv4 and IPv6 and is the preferred
// way to match the transport protocol in family-agnostic (inet) tables.
//
// Example:
//
//	// Match TCP (protocol number 6)
//	exprs := nfthelper.MatchL4Proto(unix.IPPROTO_TCP)
func MatchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	}
}

// ---------------------------------------------------------------------------
// Meta matchers
// ---------------------------------------------------------------------------

// MatchIifname returns expressions that match the input interface name using
// the meta iifname key. The name is null-terminated and padded to the kernel's
// IFNAMSIZ (16 bytes).
//
// Example:
//
//	exprs := nfthelper.MatchIifname("eth0")
func MatchIifname(name string) []expr.Any {
	return matchIfname(expr.MetaKeyIIFNAME, name)
}

// MatchOifname returns expressions that match the output interface name using
// the meta oifname key.
//
// Example:
//
//	exprs := nfthelper.MatchOifname("wg0")
func MatchOifname(name string) []expr.Any {
	return matchIfname(expr.MetaKeyOIFNAME, name)
}

func matchIfname(key expr.MetaKey, name string) []expr.Any {
	// Pad name to IFNAMSIZ (16 bytes) with null bytes.
	ifname := make([]byte, 16)
	copy(ifname, []byte(name))
	return []expr.Any{
		&expr.Meta{
			Key:      key,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname,
		},
	}
}

// MatchMark returns expressions that match the packet mark (meta mark) against
// the given 32-bit value using native-endian encoding.
//
// Example:
//
//	exprs := nfthelper.MatchMark(0x42)
func MatchMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark),
		},
	}
}

// SetMark returns expressions that set the packet mark (meta mark) to the
// given 32-bit value. This loads the value into a register via an immediate
// expression and then writes it to the meta mark using a source-register meta
// expression.
//
// Example:
//
//	exprs := nfthelper.SetMark(0x42)
func SetMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// MatchNfproto returns expressions that match the nfproto meta key, which
// identifies the network-layer protocol family (e.g., unix.NFPROTO_IPV4 or
// unix.NFPROTO_IPV6). This is useful in inet/bridge tables to distinguish
// IPv4 from IPv6 traffic.
//
// Example:
//
//	exprs := nfthelper.MatchNfproto(unix.NFPROTO_IPV4)
func MatchNfproto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto},
		},
	}
}

// ---------------------------------------------------------------------------
// CT matchers
// ---------------------------------------------------------------------------

// ctStateBits maps conntrack state names to their bitmask values.
var ctStateBits = map[string]uint32{
	"invalid":     1 << 0, // IP_CT_INVALID (bit 0)
	"new":         1 << 3, // IP_CT_NEW (bit 3)
	"established": 1 << 1, // IP_CT_ESTABLISHED (bit 1)
	"related":     1 << 2, // IP_CT_RELATED (bit 2)
	"untracked":   1 << 6, // IP_CT_UNTRACKED (bit 6)
}

// MatchCTState returns expressions that match one or more conntrack states.
// State names are case-insensitive and may include: "new", "established",
// "related", "invalid", and "untracked". Multiple states are OR'd together
// into a single bitmask and matched using a bitwise AND + cmp != 0 pattern.
//
// Example:
//
//	// Match established or related connections
//	exprs := nfthelper.MatchCTState("established", "related")
//
//	// Match new connections
//	exprs := nfthelper.MatchCTState("new")
func MatchCTState(states ...string) []expr.Any {
	var mask uint32
	for _, s := range states {
		if bit, ok := ctStateBits[strings.ToLower(s)]; ok {
			mask |= bit
		}
	}
	if mask == 0 {
		return nil
	}
	maskBytes := binaryutil.NativeEndian.PutUint32(mask)
	return []expr.Any{
		// Load ct state into register 1.
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		// Bitwise AND with the desired state mask.
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           maskBytes,
			Xor:            []byte{0, 0, 0, 0},
		},
		// Compare result != 0 (any of the requested states is set).
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
	}
}

// MatchCTMark returns expressions that match the conntrack mark against the
// given 32-bit value.
//
// Example:
//
//	exprs := nfthelper.MatchCTMark(0x1)
func MatchCTMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyMARK,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark),
		},
	}
}

// SetCTMark returns expressions that set the conntrack mark to the given
// 32-bit value. This loads the value into a register via an immediate
// expression and writes it to the ct mark using a source-register ct
// expression.
//
// Example:
//
//	exprs := nfthelper.SetCTMark(0x1)
func SetCTMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark),
		},
		&expr.Ct{
			Key:            expr.CtKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// ---------------------------------------------------------------------------
// Verdict functions
// ---------------------------------------------------------------------------

// Accept returns an accept verdict expression that terminates rule evaluation
// and accepts the packet.
//
// Example:
//
//	exprs := nfthelper.Accept()
func Accept() []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// Drop returns a drop verdict expression that terminates rule evaluation and
// drops the packet.
//
// Example:
//
//	exprs := nfthelper.Drop()
func Drop() []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// Return returns a return verdict expression that returns to the calling chain.
//
// Example:
//
//	exprs := nfthelper.Return()
func Return() []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictReturn},
	}
}

// Continue returns a continue verdict expression that continues evaluation
// with the next rule.
//
// Example:
//
//	exprs := nfthelper.Continue()
func Continue() []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictContinue},
	}
}

// Jump returns a jump verdict expression that transfers evaluation to the
// named chain, returning to the current chain after the target chain is
// fully evaluated.
//
// Example:
//
//	exprs := nfthelper.Jump("my_chain")
func Jump(chain string) []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictJump, Chain: chain},
	}
}

// Goto returns a goto verdict expression that transfers evaluation to the
// named chain without returning to the current chain.
//
// Example:
//
//	exprs := nfthelper.Goto("my_chain")
func Goto(chain string) []expr.Any {
	return []expr.Any{
		&expr.Verdict{Kind: expr.VerdictGoto, Chain: chain},
	}
}

// ---------------------------------------------------------------------------
// Action functions
// ---------------------------------------------------------------------------

// Counter returns a counter expression that counts matching packets and bytes.
// The counter starts at zero; the kernel increments it automatically.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchTCPDport(80),
//	    nfthelper.Counter(),
//	    nfthelper.Accept(),
//	)
func Counter() []expr.Any {
	return []expr.Any{
		&expr.Counter{},
	}
}

// Log returns a log expression that logs matching packets to the kernel log
// with the given prefix string. The prefix appears in dmesg/syslog output.
//
// Example:
//
//	exprs := nfthelper.Log("NFT DROP: ")
func Log(prefix string) []expr.Any {
	return []expr.Any{
		&expr.Log{
			Key:  unix.NFTA_LOG_PREFIX,
			Data: []byte(prefix),
		},
	}
}

// LogLevel returns a log expression with both a prefix and a severity level.
// Valid level values are: "emerg", "alert", "crit", "err", "warn"/"warning",
// "notice", "info", "debug".
//
// Example:
//
//	exprs := nfthelper.LogLevel("NFT WARN: ", "warn")
func LogLevel(prefix string, level string) []expr.Any {
	l := parseLogLevelHelper(level)
	return []expr.Any{
		&expr.Log{
			Key:   unix.NFTA_LOG_PREFIX | unix.NFTA_LOG_LEVEL,
			Data:  []byte(prefix),
			Level: l,
		},
	}
}

func parseLogLevelHelper(s string) expr.LogLevel {
	levels := map[string]expr.LogLevel{
		"emerg": expr.LogLevelEmerg, "alert": expr.LogLevelAlert,
		"crit": expr.LogLevelCrit, "err": expr.LogLevelErr,
		"warn": expr.LogLevelWarning, "warning": expr.LogLevelWarning,
		"notice": expr.LogLevelNotice, "info": expr.LogLevelInfo,
		"debug": expr.LogLevelDebug,
	}
	if l, ok := levels[strings.ToLower(s)]; ok {
		return l
	}
	return expr.LogLevelWarning
}

// Limit returns a rate-limiting expression that allows up to rate packets per
// unit of time. The unit parameter accepts: "second", "minute", "hour",
// "day", "week".
//
// Example:
//
//	// Allow 10 packets per second
//	exprs := nfthelper.Limit(10, "second")
func Limit(rate uint64, unit string) []expr.Any {
	return []expr.Any{
		&expr.Limit{
			Type:  expr.LimitTypePkts,
			Rate:  rate,
			Unit:  parseLimitUnitHelper(unit),
			Burst: 0,
		},
	}
}

// LimitBurst returns a rate-limiting expression with an explicit burst
// allowance. The burst parameter specifies how many packets above the rate
// are permitted in a burst before rate limiting takes effect.
//
// Example:
//
//	// Allow 25 packets per second with a burst of 50
//	exprs := nfthelper.LimitBurst(25, "second", 50)
func LimitBurst(rate uint64, unit string, burst uint32) []expr.Any {
	return []expr.Any{
		&expr.Limit{
			Type:  expr.LimitTypePkts,
			Rate:  rate,
			Unit:  parseLimitUnitHelper(unit),
			Burst: burst,
		},
	}
}

func parseLimitUnitHelper(s string) expr.LimitTime {
	switch strings.ToLower(s) {
	case "second", "sec", "s":
		return expr.LimitTimeSecond
	case "minute", "min", "m":
		return expr.LimitTimeMinute
	case "hour", "h":
		return expr.LimitTimeHour
	case "day", "d":
		return expr.LimitTimeDay
	case "week", "w":
		return expr.LimitTimeWeek
	default:
		return expr.LimitTimeSecond
	}
}

// Reject returns a reject expression that sends an ICMP destination
// unreachable (port unreachable) message back to the sender. This uses
// NFT_REJECT_ICMP_UNREACH with code 3 (port unreachable) for IPv4.
//
// Example:
//
//	exprs := nfthelper.Reject()
func Reject() []expr.Any {
	return []expr.Any{
		&expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			Code: 3, // ICMP port unreachable
		},
	}
}

// RejectTCPReset returns a reject expression that sends a TCP RST packet.
// This should be used only for TCP traffic.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchL4Proto(unix.IPPROTO_TCP),
//	    nfthelper.MatchTCPDport(80),
//	    nfthelper.RejectTCPReset(),
//	)
func RejectTCPReset() []expr.Any {
	return []expr.Any{
		&expr.Reject{
			Type: unix.NFT_REJECT_TCP_RST,
			Code: 0,
		},
	}
}

// icmpRejectCodes maps common ICMP reject code names to their numeric values.
var icmpRejectCodes = map[string]uint8{
	"net-unreachable":       0,
	"host-unreachable":      1,
	"prot-unreachable":      2,
	"port-unreachable":      3,
	"net-prohibited":        9,
	"host-prohibited":       10,
	"admin-prohibited":      13,
}

// RejectICMP returns a reject expression with an ICMP unreachable code
// specified by name. Supported code names include: "net-unreachable",
// "host-unreachable", "prot-unreachable", "port-unreachable",
// "net-prohibited", "host-prohibited", "admin-prohibited".
//
// Example:
//
//	exprs := nfthelper.RejectICMP("admin-prohibited")
func RejectICMP(code string) []expr.Any {
	c, ok := icmpRejectCodes[code]
	if !ok {
		c = 3 // default to port unreachable
	}
	return []expr.Any{
		&expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			Code: c,
		},
	}
}

// Masquerade returns a masquerade expression for source NAT. The source
// address of outgoing packets is automatically rewritten to the address of
// the outgoing interface.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchOifname("eth0"),
//	    nfthelper.Masquerade(),
//	)
func Masquerade() []expr.Any {
	return []expr.Any{
		&expr.Masq{},
	}
}

// MasqueradeRandom returns a masquerade expression with randomized source
// port mapping. This is equivalent to iptables --random.
//
// Example:
//
//	exprs := nfthelper.MasqueradeRandom()
func MasqueradeRandom() []expr.Any {
	return []expr.Any{
		&expr.Masq{
			Random: true,
		},
	}
}

// SNAT returns expressions that perform source NAT to the specified IPv4
// address. The address is loaded into a register via an immediate expression,
// then the NAT expression reads it.
//
// Example:
//
//	exprs := nfthelper.SNAT("203.0.113.1")
func SNAT(addr string) []expr.Any {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	family := uint32(unix.NFPROTO_IPV4)
	ipBytes := []byte(ip4)
	if ip4 == nil {
		ip6 := ip.To16()
		if ip6 == nil {
			return nil
		}
		family = uint32(unix.NFPROTO_IPV6)
		ipBytes = []byte(ip6)
	}
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     ipBytes,
		},
		&expr.NAT{
			Type:       expr.NATTypeSourceNAT,
			Family:     family,
			RegAddrMin: 1,
		},
	}
}

// DNAT returns expressions that perform destination NAT to the specified
// IPv4 or IPv6 address. The address is loaded into a register via an
// immediate expression.
//
// Example:
//
//	exprs := nfthelper.DNAT("10.0.0.1")
func DNAT(addr string) []expr.Any {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	family := uint32(unix.NFPROTO_IPV4)
	ipBytes := []byte(ip4)
	if ip4 == nil {
		ip6 := ip.To16()
		if ip6 == nil {
			return nil
		}
		family = uint32(unix.NFPROTO_IPV6)
		ipBytes = []byte(ip6)
	}
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     ipBytes,
		},
		&expr.NAT{
			Type:       expr.NATTypeDestNAT,
			Family:     family,
			RegAddrMin: 1,
		},
	}
}

// DNATPort returns expressions that perform destination NAT to the specified
// address and port. The address is loaded into register 1 and the port into
// register 2, both consumed by the NAT expression.
//
// Example:
//
//	exprs := nfthelper.DNATPort("10.0.0.1", 8080)
func DNATPort(addr string, port uint16) []expr.Any {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	family := uint32(unix.NFPROTO_IPV4)
	ipBytes := []byte(ip4)
	if ip4 == nil {
		ip6 := ip.To16()
		if ip6 == nil {
			return nil
		}
		family = uint32(unix.NFPROTO_IPV6)
		ipBytes = []byte(ip6)
	}
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     ipBytes,
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      family,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// Notrack returns a notrack expression that disables connection tracking for
// matching packets.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchUDPDport(53),
//	    nfthelper.Notrack(),
//	)
func Notrack() []expr.Any {
	return []expr.Any{
		&expr.Notrack{},
	}
}

// FlowOffload returns a flow offload expression that offloads matching
// connections to the named flowtable for hardware/software fast-path
// forwarding.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.MatchCTState("established"),
//	    nfthelper.FlowOffload("ft0"),
//	)
func FlowOffload(name string) []expr.Any {
	return []expr.Any{
		&expr.FlowOffload{Name: name},
	}
}

// ---------------------------------------------------------------------------
// Debugging and error helpers
// ---------------------------------------------------------------------------

// ExprString returns a human-readable summary of an expression slice, useful
// for debug logging. Each expression is printed as its Go type name.
//
// Example:
//
//	fmt.Println(nfthelper.ExprString(exprs))
//	// Output: [*expr.Meta *expr.Cmp *expr.Verdict]
func ExprString(exprs []expr.Any) string {
	parts := make([]string, len(exprs))
	for i, e := range exprs {
		parts[i] = fmt.Sprintf("%T", e)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
