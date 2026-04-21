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
// Helper: protocol name to byte
// ---------------------------------------------------------------------------

// parseProtoHelper maps a protocol name to its IP protocol number.
// Supported names: tcp, udp, icmp, icmpv6, sctp, dccp, gre, esp, ah, comp,
// udplite. Returns 0 if the name is unknown.
func parseProtoHelper(s string) byte {
	protos := map[string]byte{
		"tcp":     6,
		"udp":     17,
		"icmp":    1,
		"icmpv6":  58,
		"sctp":    132,
		"dccp":    33,
		"gre":     47,
		"esp":     50,
		"ah":      51,
		"comp":    108,
		"udplite": 136,
	}
	if v, ok := protos[strings.ToLower(s)]; ok {
		return v
	}
	return 0
}

// ---------------------------------------------------------------------------
// Helper: L4 protocol + payload match
// ---------------------------------------------------------------------------

// protoAndPayload returns expressions that first match the L4 protocol via
// meta l4proto and then compare a transport-header payload field against the
// given data bytes.
func protoAndPayload(proto byte, offset, length uint32, data []byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

// ---------------------------------------------------------------------------
// IP header field matchers
// ---------------------------------------------------------------------------

// MatchIPTTL returns expressions that match the IPv4 TTL field (1 byte at
// network header offset 8).
func MatchIPTTL(ttl uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{ttl},
		},
	}
}

// MatchIPDSCP returns expressions that match the IPv4 DSCP field. The DSCP
// value occupies the upper 6 bits of the TOS byte (offset 1, len 1). A
// bitwise mask of 0xfc is applied and the result is compared against the
// dscp value shifted left by 2.
func MatchIPDSCP(dscp uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       1,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0xfc},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{dscp << 2},
		},
	}
}

// MatchIPLength returns expressions that match the IPv4 total length field
// (2 bytes at network header offset 2, big-endian).
func MatchIPLength(length uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(length),
		},
	}
}

// MatchIPId returns expressions that match the IPv4 identification field
// (2 bytes at network header offset 4, big-endian).
func MatchIPId(id uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       4,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(id),
		},
	}
}

// MatchIPFragOff returns expressions that match the IPv4 fragment offset field
// (2 bytes at network header offset 6, big-endian).
func MatchIPFragOff(fragoff uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(fragoff),
		},
	}
}

// MatchIPVersion returns expressions that match the IPv4 version nibble (upper
// 4 bits of the first byte at network header offset 0). A bitwise mask of 0xf0
// is applied before comparison.
func MatchIPVersion(version uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0xf0},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{version << 4},
		},
	}
}

// MatchIPHdrLength returns expressions that match the IPv4 header length nibble
// (lower 4 bits of the first byte at network header offset 0). A bitwise mask
// of 0x0f is applied before comparison.
func MatchIPHdrLength(hdrlength uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x0f},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{hdrlength},
		},
	}
}

// MatchIPChecksum returns expressions that match the IPv4 header checksum field
// (2 bytes at network header offset 10, big-endian).
func MatchIPChecksum(checksum uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       10,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(checksum),
		},
	}
}

// ---------------------------------------------------------------------------
// IPv6 header field matchers
// ---------------------------------------------------------------------------

// MatchIP6HopLimit returns expressions that match the IPv6 hop limit field
// (1 byte at network header offset 7).
func MatchIP6HopLimit(hoplimit uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       7,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{hoplimit},
		},
	}
}

// MatchIP6FlowLabel returns expressions that match the IPv6 flow label field.
// The flow label is the lower 20 bits of the first 4 bytes of the IPv6 header
// (offset 0, len 4). A bitwise mask of 0x000fffff is applied (big-endian).
func MatchIP6FlowLabel(flowlabel uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0x00, 0x0f, 0xff, 0xff},
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(flowlabel),
		},
	}
}

// MatchIP6NextHdr returns expressions that match the IPv6 next header field
// (1 byte at network header offset 6) using a protocol name such as "tcp",
// "udp", "icmpv6", etc.
func MatchIP6NextHdr(proto string) []expr.Any {
	p := parseProtoHelper(proto)
	if p == 0 {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{p},
		},
	}
}

// MatchIP6Length returns expressions that match the IPv6 payload length field
// (2 bytes at network header offset 4, big-endian).
func MatchIP6Length(length uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       4,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(length),
		},
	}
}

// MatchIP6Version returns expressions that match the IPv6 version nibble (upper
// 4 bits of the first byte at network header offset 0). A bitwise mask of 0xf0
// is applied before comparison.
func MatchIP6Version(version uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0xf0},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{version << 4},
		},
	}
}

// MatchIP6DSCP returns expressions that match the IPv6 DSCP field. The DSCP
// value is encoded in bits 4-9 of the first 2 bytes of the IPv6 header
// (offset 0, len 2). A big-endian mask of 0x0fc0 is applied and the result
// is compared against the dscp value shifted left by 6.
func MatchIP6DSCP(dscp uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          2,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0x0f, 0xc0},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(uint16(dscp) << 6),
		},
	}
}

// ---------------------------------------------------------------------------
// TCP field matchers
// ---------------------------------------------------------------------------

// tcpFlagBits maps TCP flag names to their bit positions in the flags byte.
var tcpFlagBits = map[string]byte{
	"fin": 0x01,
	"syn": 0x02,
	"rst": 0x04,
	"psh": 0x08,
	"ack": 0x10,
	"urg": 0x20,
	"ecn": 0x40,
	"cwr": 0x80,
}

// MatchTCPFlags returns expressions that match TCP flags. The flags parameter
// is a "|"-separated list of flag names: fin, syn, rst, psh, ack, urg, ecn,
// cwr. A bitwise mask is built from the specified flags and compared against
// the TCP flags byte (offset 13, len 1).
//
// Example:
//
//	exprs := nfthelper.MatchTCPFlags("syn|ack")
func MatchTCPFlags(flags string) []expr.Any {
	var mask byte
	for _, f := range strings.Split(flags, "|") {
		if bit, ok := tcpFlagBits[strings.TrimSpace(strings.ToLower(f))]; ok {
			mask |= bit
		}
	}
	if mask == 0 {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{mask},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{mask},
		},
	}
}

// MatchTCPSequence returns expressions that match the TCP sequence number
// (4 bytes at transport header offset 4, big-endian).
func MatchTCPSequence(seq uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       4,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(seq),
		},
	}
}

// MatchTCPAckSeq returns expressions that match the TCP acknowledgment
// sequence number (4 bytes at transport header offset 8, big-endian).
func MatchTCPAckSeq(ackseq uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       8,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(ackseq),
		},
	}
}

// MatchTCPDoff returns expressions that match the TCP data offset field (upper
// nibble of the byte at transport header offset 12). A bitwise mask of 0xf0 is
// applied before comparison.
func MatchTCPDoff(doff uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       12,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0xf0},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{doff << 4},
		},
	}
}

// MatchTCPWindow returns expressions that match the TCP window size field
// (2 bytes at transport header offset 14, big-endian).
func MatchTCPWindow(window uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       14,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(window),
		},
	}
}

// MatchTCPChecksum returns expressions that match the TCP checksum field
// (2 bytes at transport header offset 16, big-endian).
func MatchTCPChecksum(checksum uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       16,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(checksum),
		},
	}
}

// MatchTCPUrgPtr returns expressions that match the TCP urgent pointer field
// (2 bytes at transport header offset 18, big-endian).
func MatchTCPUrgPtr(urgptr uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       18,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(urgptr),
		},
	}
}

// ---------------------------------------------------------------------------
// UDP field matchers
// ---------------------------------------------------------------------------

// MatchUDPLength returns expressions that match the UDP length field (2 bytes
// at transport header offset 4, big-endian).
func MatchUDPLength(length uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       4,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(length),
		},
	}
}

// MatchUDPChecksum returns expressions that match the UDP checksum field
// (2 bytes at transport header offset 6, big-endian).
func MatchUDPChecksum(checksum uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       6,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(checksum),
		},
	}
}

// ---------------------------------------------------------------------------
// ICMP field matchers
// ---------------------------------------------------------------------------

// MatchICMPCode returns expressions that match the ICMPv4 code field (1 byte
// at transport header offset 1).
func MatchICMPCode(code uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       1,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// MatchICMPId returns expressions that match the ICMPv4 identifier field
// (2 bytes at transport header offset 4, big-endian).
func MatchICMPId(id uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       4,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(id),
		},
	}
}

// MatchICMPSequence returns expressions that match the ICMPv4 sequence number
// field (2 bytes at transport header offset 6, big-endian).
func MatchICMPSequence(seq uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       6,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(seq),
		},
	}
}

// ---------------------------------------------------------------------------
// ICMPv6 field matchers
// ---------------------------------------------------------------------------

// MatchICMPv6Code returns expressions that match the ICMPv6 code field (1 byte
// at transport header offset 1).
func MatchICMPv6Code(code uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       1,
			Len:          1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// MatchICMPv6Id returns expressions that match the ICMPv6 identifier field
// (2 bytes at transport header offset 4, big-endian).
func MatchICMPv6Id(id uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       4,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(id),
		},
	}
}

// MatchICMPv6Sequence returns expressions that match the ICMPv6 sequence number
// field (2 bytes at transport header offset 6, big-endian).
func MatchICMPv6Sequence(seq uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       6,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(seq),
		},
	}
}

// ---------------------------------------------------------------------------
// Ethernet matchers
// ---------------------------------------------------------------------------

// MatchEtherSaddr returns expressions that match the Ethernet source MAC
// address (6 bytes at link-layer header offset 6).
func MatchEtherSaddr(mac string) []expr.Any {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       6,
			Len:          6,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(hw),
		},
	}
}

// MatchEtherDaddr returns expressions that match the Ethernet destination MAC
// address (6 bytes at link-layer header offset 0).
func MatchEtherDaddr(mac string) []expr.Any {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       0,
			Len:          6,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte(hw),
		},
	}
}

// MatchEtherType returns expressions that match the EtherType field (2 bytes
// at link-layer header offset 12, big-endian).
func MatchEtherType(ethtype uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       12,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(ethtype),
		},
	}
}

// ---------------------------------------------------------------------------
// VLAN matchers
// ---------------------------------------------------------------------------

// MatchVLANId returns expressions that match the 802.1Q VLAN ID (lower 12 bits
// of the 2-byte TCI field at link-layer header offset 14). A big-endian mask
// of 0x0fff is applied before comparison.
func MatchVLANId(id uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       14,
			Len:          2,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0x0f, 0xff},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(id),
		},
	}
}

// MatchVLANPcp returns expressions that match the 802.1Q VLAN PCP (priority
// code point), which occupies the upper 3 bits of the 2-byte TCI field at
// link-layer header offset 14. A big-endian mask of 0xe000 is applied and the
// result is compared against the pcp value shifted left by 13.
func MatchVLANPcp(pcp uint8) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       14,
			Len:          2,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0xe0, 0x00},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(uint16(pcp) << 13),
		},
	}
}

// ---------------------------------------------------------------------------
// ARP matchers
// ---------------------------------------------------------------------------

// arpOperations maps ARP operation names to their numeric values.
var arpOperations = map[string]uint16{
	"request":   1,
	"reply":     2,
	"rrequest":  3,
	"rreply":    4,
	"inrequest": 8,
	"inreply":   9,
	"nak":       10,
}

// MatchARPOperation returns expressions that match the ARP operation field
// (2 bytes at network header offset 6, big-endian). The op parameter is a
// name such as "request", "reply", "rrequest", "rreply", "inrequest",
// "inreply", or "nak".
func MatchARPOperation(op string) []expr.Any {
	code, ok := arpOperations[strings.ToLower(op)]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(code),
		},
	}
}

// MatchARPHtype returns expressions that match the ARP hardware type field
// (2 bytes at network header offset 0, big-endian).
func MatchARPHtype(htype uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       0,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(htype),
		},
	}
}

// MatchARPPtype returns expressions that match the ARP protocol type field
// (2 bytes at network header offset 2, big-endian).
func MatchARPPtype(ptype uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(ptype),
		},
	}
}

// ---------------------------------------------------------------------------
// SCTP matchers
// ---------------------------------------------------------------------------

// MatchSCTPDport returns expressions that match the SCTP destination port
// (transport offset 2, len 2), preceded by a meta l4proto match for SCTP (132).
func MatchSCTPDport(port uint16) []expr.Any {
	return protoAndPayload(132, 2, 2, binaryutil.BigEndian.PutUint16(port))
}

// MatchSCTPSport returns expressions that match the SCTP source port
// (transport offset 0, len 2), preceded by a meta l4proto match for SCTP (132).
func MatchSCTPSport(port uint16) []expr.Any {
	return protoAndPayload(132, 0, 2, binaryutil.BigEndian.PutUint16(port))
}

// MatchSCTPVtag returns expressions that match the SCTP verification tag
// (transport offset 4, len 4), preceded by a meta l4proto match for SCTP (132).
func MatchSCTPVtag(vtag uint32) []expr.Any {
	return protoAndPayload(132, 4, 4, binaryutil.BigEndian.PutUint32(vtag))
}

// ---------------------------------------------------------------------------
// DCCP matchers
// ---------------------------------------------------------------------------

// dccpTypes maps DCCP packet type names to their numeric values.
var dccpTypes = map[string]byte{
	"request":  0,
	"response": 1,
	"data":     2,
	"ack":      3,
	"dataack":  4,
	"closereq": 5,
	"close":    6,
	"reset":    7,
	"sync":     8,
	"syncack":  9,
}

// MatchDCCPDport returns expressions that match the DCCP destination port
// (transport offset 2, len 2), preceded by a meta l4proto match for DCCP (33).
func MatchDCCPDport(port uint16) []expr.Any {
	return protoAndPayload(33, 2, 2, binaryutil.BigEndian.PutUint16(port))
}

// MatchDCCPSport returns expressions that match the DCCP source port
// (transport offset 0, len 2), preceded by a meta l4proto match for DCCP (33).
func MatchDCCPSport(port uint16) []expr.Any {
	return protoAndPayload(33, 0, 2, binaryutil.BigEndian.PutUint16(port))
}

// MatchDCCPType returns expressions that match the DCCP packet type field
// (transport offset 8, len 1), preceded by a meta l4proto match for DCCP (33).
// The typeName parameter is one of: request, response, data, ack, dataack,
// closereq, close, reset, sync, syncack.
func MatchDCCPType(typeName string) []expr.Any {
	code, ok := dccpTypes[strings.ToLower(typeName)]
	if !ok {
		return nil
	}
	return protoAndPayload(33, 8, 1, []byte{code})
}

// ---------------------------------------------------------------------------
// ESP matchers
// ---------------------------------------------------------------------------

// MatchESPSpi returns expressions that match the ESP SPI field (transport
// offset 0, len 4), preceded by a meta l4proto match for ESP (50).
func MatchESPSpi(spi uint32) []expr.Any {
	return protoAndPayload(50, 0, 4, binaryutil.BigEndian.PutUint32(spi))
}

// MatchESPSequence returns expressions that match the ESP sequence number field
// (transport offset 4, len 4), preceded by a meta l4proto match for ESP (50).
func MatchESPSequence(seq uint32) []expr.Any {
	return protoAndPayload(50, 4, 4, binaryutil.BigEndian.PutUint32(seq))
}

// ---------------------------------------------------------------------------
// AH matchers
// ---------------------------------------------------------------------------

// MatchAHSpi returns expressions that match the AH SPI field (transport
// offset 4, len 4), preceded by a meta l4proto match for AH (51).
func MatchAHSpi(spi uint32) []expr.Any {
	return protoAndPayload(51, 4, 4, binaryutil.BigEndian.PutUint32(spi))
}

// MatchAHSequence returns expressions that match the AH sequence number field
// (transport offset 8, len 4), preceded by a meta l4proto match for AH (51).
func MatchAHSequence(seq uint32) []expr.Any {
	return protoAndPayload(51, 8, 4, binaryutil.BigEndian.PutUint32(seq))
}

// MatchAHHdrLength returns expressions that match the AH header length field
// (transport offset 1, len 1), preceded by a meta l4proto match for AH (51).
func MatchAHHdrLength(hdrlength uint8) []expr.Any {
	return protoAndPayload(51, 1, 1, []byte{hdrlength})
}

// ---------------------------------------------------------------------------
// COMP matchers
// ---------------------------------------------------------------------------

// MatchCOMPCpi returns expressions that match the IPComp CPI field (transport
// offset 2, len 2), preceded by a meta l4proto match for COMP (108).
func MatchCOMPCpi(cpi uint16) []expr.Any {
	return protoAndPayload(108, 2, 2, binaryutil.BigEndian.PutUint16(cpi))
}

// MatchCOMPNextHdr returns expressions that match the IPComp next header field
// (transport offset 0, len 1), preceded by a meta l4proto match for COMP (108).
// The proto parameter is a protocol name such as "tcp", "udp", etc.
func MatchCOMPNextHdr(proto string) []expr.Any {
	p := parseProtoHelper(proto)
	if p == 0 {
		return nil
	}
	return protoAndPayload(108, 0, 1, []byte{p})
}

// ---------------------------------------------------------------------------
// UDPLite matchers
// ---------------------------------------------------------------------------

// MatchUDPLiteDport returns expressions that match the UDP-Lite destination
// port (transport offset 2, len 2), preceded by a meta l4proto match for
// UDP-Lite (136).
func MatchUDPLiteDport(port uint16) []expr.Any {
	return protoAndPayload(136, 2, 2, binaryutil.BigEndian.PutUint16(port))
}

// MatchUDPLiteSport returns expressions that match the UDP-Lite source port
// (transport offset 0, len 2), preceded by a meta l4proto match for
// UDP-Lite (136).
func MatchUDPLiteSport(port uint16) []expr.Any {
	return protoAndPayload(136, 0, 2, binaryutil.BigEndian.PutUint16(port))
}

// ---------------------------------------------------------------------------
// Additional meta matchers
// ---------------------------------------------------------------------------

// MatchIif returns expressions that match the input interface index using the
// meta iif key (32-bit native-endian).
func MatchIif(iif uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIF,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(iif),
		},
	}
}

// MatchOif returns expressions that match the output interface index using the
// meta oif key (32-bit native-endian).
func MatchOif(oif uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyOIF,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(oif),
		},
	}
}

// MatchIiftype returns expressions that match the input interface type using
// the meta iiftype key (16-bit native-endian).
func MatchIiftype(iftype uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFTYPE,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint16(iftype),
		},
	}
}

// MatchOiftype returns expressions that match the output interface type using
// the meta oiftype key (16-bit native-endian).
func MatchOiftype(iftype uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyOIFTYPE,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint16(iftype),
		},
	}
}

// MatchIifgroup returns expressions that match the input interface group using
// the meta iifgroup key (32-bit native-endian).
func MatchIifgroup(group uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIFGROUP,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(group),
		},
	}
}

// MatchOifgroup returns expressions that match the output interface group using
// the meta oifgroup key (32-bit native-endian).
func MatchOifgroup(group uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyOIFGROUP,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(group),
		},
	}
}

// MatchMetaLength returns expressions that match the packet length using the
// meta len key (32-bit native-endian).
func MatchMetaLength(length uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyLEN,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(length),
		},
	}
}

// MatchMetaProtocol returns expressions that match the EtherType protocol using
// the meta protocol key (16-bit big-endian, as it is a network-layer value).
func MatchMetaProtocol(proto uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyPROTOCOL,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(proto),
		},
	}
}

// pktTypes maps packet type names to their numeric values.
var pktTypes = map[string]byte{
	"host":      0,
	"broadcast": 1,
	"multicast": 2,
	"other":     3,
}

// MatchPktType returns expressions that match the packet type using the meta
// pkttype key. The pkttype parameter is a name: "host", "broadcast",
// "multicast", or "other".
func MatchPktType(pkttype string) []expr.Any {
	code, ok := pktTypes[strings.ToLower(pkttype)]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyPKTTYPE,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// MatchSkuid returns expressions that match the socket UID using the meta
// skuid key (32-bit native-endian).
func MatchSkuid(uid uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeySKUID,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(uid),
		},
	}
}

// MatchSkgid returns expressions that match the socket GID using the meta
// skgid key (32-bit native-endian).
func MatchSkgid(gid uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeySKGID,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(gid),
		},
	}
}

// MatchCpu returns expressions that match the CPU number using the meta cpu
// key (32-bit native-endian).
func MatchCpu(cpu uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyCPU,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(cpu),
		},
	}
}

// MatchCgroup returns expressions that match the cgroup v2 classid using the
// meta cgroup key (32-bit native-endian).
func MatchCgroup(cgroup uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyCGROUP,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(cgroup),
		},
	}
}

// ---------------------------------------------------------------------------
// Additional meta set actions
// ---------------------------------------------------------------------------

// SetPriority returns expressions that set the packet priority (meta priority)
// to the given 32-bit value.
func SetPriority(priority uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(priority),
		},
		&expr.Meta{
			Key:            expr.MetaKeyPRIORITY,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// SetNftrace returns expressions that enable or disable nftrace for matching
// packets. When enable is true, nftrace is set to 1; otherwise it is set to 0.
func SetNftrace(enable bool) []expr.Any {
	var val byte
	if enable {
		val = 1
	}
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     []byte{val},
		},
		&expr.Meta{
			Key:            expr.MetaKeyNFTRACE,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// ---------------------------------------------------------------------------
// Additional CT matchers
// ---------------------------------------------------------------------------

// ctDirections maps conntrack direction names to their numeric values.
var ctDirections = map[string]byte{
	"original": 0,
	"reply":    1,
}

// MatchCTDirection returns expressions that match the conntrack direction.
// The dir parameter is "original" or "reply".
func MatchCTDirection(dir string) []expr.Any {
	code, ok := ctDirections[strings.ToLower(dir)]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyDIRECTION,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// ctStatusBits maps conntrack status flag names to their bitmask values.
var ctStatusBits = map[string]uint32{
	"expected":   1,
	"seen-reply": 2,
	"assured":    4,
	"confirmed":  8,
	"snat":       16,
	"dnat":       32,
	"dying":      512,
}

// MatchCTStatus returns expressions that match one or more conntrack status
// flags. Flag names are OR'd together into a bitmask and matched using a
// bitwise AND + cmp != 0 pattern. Supported names: "expected", "seen-reply",
// "assured", "confirmed", "snat", "dnat", "dying".
func MatchCTStatus(statuses ...string) []expr.Any {
	var mask uint32
	for _, s := range statuses {
		if bit, ok := ctStatusBits[strings.ToLower(s)]; ok {
			mask |= bit
		}
	}
	if mask == 0 {
		return nil
	}
	maskBytes := binaryutil.NativeEndian.PutUint32(mask)
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATUS,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           maskBytes,
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
	}
}

// MatchCTZone returns expressions that match the conntrack zone (16-bit
// native-endian).
func MatchCTZone(zone uint16) []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyZONE,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint16(zone),
		},
	}
}

// ctL3Protos maps L3 protocol family names to their numeric values.
var ctL3Protos = map[string]byte{
	"ip":   2,
	"ipv4": 2,
	"ip6":  10,
	"ipv6": 10,
}

// MatchCTL3Proto returns expressions that match the conntrack L3 protocol
// family. The proto parameter is "ip"/"ipv4" (2) or "ip6"/"ipv6" (10).
func MatchCTL3Proto(proto string) []expr.Any {
	code, ok := ctL3Protos[strings.ToLower(proto)]
	if !ok {
		return nil
	}
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyL3PROTOCOL,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{code},
		},
	}
}

// MatchCTProtocol returns expressions that match the conntrack L4 protocol
// using a protocol name such as "tcp", "udp", etc.
func MatchCTProtocol(proto string) []expr.Any {
	p := parseProtoHelper(proto)
	if p == 0 {
		return nil
	}
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyPROTOCOL,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{p},
		},
	}
}

// MatchCTHelper returns expressions that match the conntrack helper name. The
// helper string is null-padded to 16 bytes (IFNAMSIZ) for comparison.
func MatchCTHelper(helper string) []expr.Any {
	b := make([]byte, 16)
	copy(b, []byte(helper))
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeyHELPER,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     b,
		},
	}
}

// ---------------------------------------------------------------------------
// Additional actions
// ---------------------------------------------------------------------------

// Redirect returns expressions that redirect the packet to the specified port
// on the local machine. The port is loaded into register 1 and consumed by a
// redir expression.
func Redirect(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
		&expr.Redir{
			RegisterProtoMin: 1,
		},
	}
}

// RedirectRange returns expressions that redirect the packet to a port in the
// specified range on the local machine. The min and max ports are loaded into
// registers 1 and 2 respectively.
func RedirectRange(portMin, portMax uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(portMin),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(portMax),
		},
		&expr.Redir{
			RegisterProtoMin: 1,
			RegisterProtoMax: 2,
		},
	}
}

// Queue returns a queue expression that sends the packet to userspace via
// NFQUEUE with the specified queue number.
func Queue(num uint16) []expr.Any {
	return []expr.Any{
		&expr.Queue{
			Num: num,
		},
	}
}

// QueueBypass returns a queue expression that sends the packet to userspace
// via NFQUEUE with the specified queue number and the bypass flag set. When
// the bypass flag is set, packets are accepted if no userspace program is
// listening on the queue.
func QueueBypass(num uint16) []expr.Any {
	return []expr.Any{
		&expr.Queue{
			Num:  num,
			Flag: expr.QueueFlag(unix.NFT_QUEUE_FLAG_BYPASS),
		},
	}
}

// icmpv6RejectCodes maps ICMPv6 reject code names to their numeric values.
var icmpv6RejectCodes = map[string]uint8{
	"no-route":          0,
	"admin-prohibited":  1,
	"addr-unreachable":  3,
	"port-unreachable":  4,
}

// RejectICMPv6 returns a reject expression with an ICMPv6 unreachable code
// specified by name. Supported code names: "no-route", "admin-prohibited",
// "addr-unreachable", "port-unreachable".
func RejectICMPv6(code string) []expr.Any {
	c, ok := icmpv6RejectCodes[strings.ToLower(code)]
	if !ok {
		c = 4 // default to port-unreachable
	}
	return []expr.Any{
		&expr.Reject{
			Type: unix.NFT_REJECT_ICMP_UNREACH,
			Code: c,
		},
	}
}

// icmpxRejectCodes maps ICMPx (inet family) reject code names to the kernel
// enum values in include/uapi/linux/netfilter/nf_tables.h. The order matters:
// no-route=0, port-unreachable=1, host-unreachable=2, admin-prohibited=3.
var icmpxRejectCodes = map[string]uint8{
	"no-route":         unix.NFT_REJECT_ICMPX_NO_ROUTE,
	"port-unreachable": unix.NFT_REJECT_ICMPX_PORT_UNREACH,
	"host-unreachable": unix.NFT_REJECT_ICMPX_HOST_UNREACH,
	"admin-prohibited": unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
}

// RejectICMPx returns a reject expression for the inet family with an ICMPx
// unreachable code specified by name. Supported code names:
// "port-unreachable", "admin-prohibited", "no-route", "host-unreachable".
func RejectICMPx(code string) []expr.Any {
	c, ok := icmpxRejectCodes[strings.ToLower(code)]
	if !ok {
		c = 0 // default to port-unreachable
	}
	return []expr.Any{
		&expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: c,
		},
	}
}

// LimitBytes returns a byte-based rate-limiting expression that allows up to
// rate bytes per unit of time.
func LimitBytes(rate uint64, unit string) []expr.Any {
	return []expr.Any{
		&expr.Limit{
			Type:  expr.LimitTypePktBytes,
			Rate:  rate,
			Unit:  parseLimitUnitHelper(unit),
			Burst: 0,
		},
	}
}

// MasqueradePersistent returns a masquerade expression with the persistent
// flag set, which gives the same source address for a given connection.
func MasqueradePersistent() []expr.Any {
	return []expr.Any{
		&expr.Masq{
			Persistent: true,
		},
	}
}

// MasqueradeFullyRandom returns a masquerade expression with the fully-random
// flag set, which randomizes both the source port and the source address
// selection.
func MasqueradeFullyRandom() []expr.Any {
	return []expr.Any{
		&expr.Masq{
			FullyRandom: true,
		},
	}
}

// SNATPort returns expressions that perform source NAT to the specified IPv4
// or IPv6 address and port. The address is loaded into register 1 and the port
// into register 2.
func SNATPort(addr string, port uint16) []expr.Any {
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
			Type:        expr.NATTypeSourceNAT,
			Family:      family,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

// SNATPortRange returns expressions that perform source NAT to the specified
// IPv4 or IPv6 address with a port range. The address is loaded into register
// 1, the min port into register 2, and the max port into register 3.
func SNATPortRange(addr string, portMin, portMax uint16) []expr.Any {
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
			Data:     binaryutil.BigEndian.PutUint16(portMin),
		},
		&expr.Immediate{
			Register: 3,
			Data:     binaryutil.BigEndian.PutUint16(portMax),
		},
		&expr.NAT{
			Type:        expr.NATTypeSourceNAT,
			Family:      family,
			RegAddrMin:  1,
			RegProtoMin: 2,
			RegProtoMax: 3,
		},
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
// ===========================================================================
// Loaders — load a field into register 1 without comparing.
// Compose with Lookup() for set membership, or with the existing
// Match* functions for literal value comparison.
// ===========================================================================

// LoadIPSaddr loads the IPv4 source address (4 bytes at network header
// offset 12) into register 1.
func LoadIPSaddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
	}
}

// LoadIPDaddr loads the IPv4 destination address into register 1.
func LoadIPDaddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
	}
}

// LoadIPProtocol loads the IPv4 protocol field into register 1.
func LoadIPProtocol() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
	}
}

// LoadIPTTL loads the IPv4 TTL field into register 1.
func LoadIPTTL() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1},
	}
}

// LoadIPLength loads the IPv4 total length field into register 1.
func LoadIPLength() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2},
	}
}

// LoadIP6Saddr loads the IPv6 source address (16 bytes at offset 8) into register 1.
func LoadIP6Saddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
	}
}

// LoadIP6Daddr loads the IPv6 destination address into register 1.
func LoadIP6Daddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
	}
}

// LoadIP6NextHdr loads the IPv6 next header field into register 1.
func LoadIP6NextHdr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 1},
	}
}

// LoadIP6HopLimit loads the IPv6 hop limit field into register 1.
func LoadIP6HopLimit() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
	}
}

// LoadTCPDport loads the TCP destination port into register 1.
func LoadTCPDport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
	}
}

// LoadTCPSport loads the TCP source port into register 1.
func LoadTCPSport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
	}
}

// LoadTCPFlags loads the TCP flags byte into register 1.
func LoadTCPFlags() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
	}
}

// LoadUDPDport loads the UDP destination port into register 1.
func LoadUDPDport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
	}
}

// LoadUDPSport loads the UDP source port into register 1.
func LoadUDPSport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
	}
}

// LoadSCTPDport loads the SCTP destination port into register 1.
func LoadSCTPDport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
	}
}

// LoadSCTPSport loads the SCTP source port into register 1.
func LoadSCTPSport() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
	}
}

// LoadEtherSaddr loads the Ethernet source MAC address into register 1.
func LoadEtherSaddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
	}
}

// LoadEtherDaddr loads the Ethernet destination MAC address into register 1.
func LoadEtherDaddr() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 0, Len: 6},
	}
}

// LoadEtherType loads the Ethernet type field into register 1.
func LoadEtherType() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
	}
}

// LoadMetaIifname loads the input interface name into register 1.
func LoadMetaIifname() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
	}
}

// LoadMetaOifname loads the output interface name into register 1.
func LoadMetaOifname() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
	}
}

// LoadMetaMark loads the packet mark into register 1.
func LoadMetaMark() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
	}
}

// LoadMetaNfproto loads the nfproto (layer 3 protocol family) into register 1.
func LoadMetaNfproto() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
	}
}

// LoadMetaL4proto loads the layer 4 protocol into register 1.
func LoadMetaL4proto() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
	}
}

// LoadMetaProtocol loads the EtherType protocol into register 1.
func LoadMetaProtocol() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
	}
}

// LoadMetaIiftype loads the input interface type into register 1.
func LoadMetaIiftype() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFTYPE, Register: 1},
	}
}

// LoadMetaOiftype loads the output interface type into register 1.
func LoadMetaOiftype() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFTYPE, Register: 1},
	}
}

// LoadMetaPkttype loads the packet type into register 1.
func LoadMetaPkttype() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1},
	}
}

// LoadCTState loads the conntrack state into register 1.
func LoadCTState() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
	}
}

// LoadCTMark loads the conntrack mark into register 1.
func LoadCTMark() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
	}
}

// LoadCTStatus loads the conntrack status into register 1.
func LoadCTStatus() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
	}
}

// ===========================================================================
// Lookup — check if register 1 value is in a named set
// ===========================================================================

// Lookup checks if the value in register 1 is a member of the named set.
// Use after a Load* function.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.LoadIPSaddr(),
//	    nfthelper.Lookup("blocked_ips"),
//	    nfthelper.Drop(),
//	)
func Lookup(setName string) []expr.Any {
	return []expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: setName},
	}
}

// LookupInv checks if the value in register 1 is NOT in the named set
// (inverted lookup).
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.LoadIPSaddr(),
//	    nfthelper.LookupInv("allowed_ips"),
//	    nfthelper.Drop(),
//	)
func LookupInv(setName string) []expr.Any {
	return []expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: setName, Invert: true},
	}
}

// ===========================================================================
// Comparisons — compare register 1 value against constants or CIDRs.
// Use after a Load* function.
// ===========================================================================

// CmpEq compares register 1 for equality with the given big-endian bytes.
// The data parameter is raw bytes (e.g., a 4-byte IPv4 address or 2-byte port).
func CmpEq(data []byte) []expr.Any {
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

// CmpNeq compares register 1 for inequality.
func CmpNeq(data []byte) []expr.Any {
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: data},
	}
}

// CmpIPv4 compares register 1 against an IPv4 address or CIDR.
// For a single IP, generates a direct comparison.
// For a CIDR, generates bitwise mask + comparison.
//
// Example:
//
//	exprs := nfthelper.Combine(
//	    nfthelper.LoadIPSaddr(),
//	    nfthelper.CmpIPv4("10.0.0.0/8"),
//	    nfthelper.Drop(),
//	)
func CmpIPv4(addr string) []expr.Any {
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil
		}
		ip := ipNet.IP.To4()
		mask := net.IP(ipNet.Mask).To4()
		if ip == nil || mask == nil {
			return nil
		}
		return []expr.Any{
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte(mask),
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(ip)},
		}
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(ip4)},
	}
}

// CmpIPv6 compares register 1 against an IPv6 address or CIDR.
func CmpIPv6(addr string) []expr.Any {
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil
		}
		ip := ipNet.IP.To16()
		mask := make([]byte, 16)
		copy(mask, ipNet.Mask)
		if ip == nil {
			return nil
		}
		return []expr.Any{
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            16,
				Mask:           mask,
				Xor:            make([]byte, 16),
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(ip)},
		}
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip.To16()},
	}
}

// CmpPort compares register 1 against a big-endian port number.
func CmpPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

// CmpU8 compares register 1 against a single byte.
func CmpU8(val uint8) []expr.Any {
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{val}},
	}
}

// CmpU32Native compares register 1 against a native-endian uint32.
func CmpU32Native(val uint32) []expr.Any {
	return []expr.Any{
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(val)},
	}
}

func ExprString(exprs []expr.Any) string {
	parts := make([]string, len(exprs))
	for i, e := range exprs {
		parts[i] = fmt.Sprintf("%T", e)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
