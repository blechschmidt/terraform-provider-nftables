package provider

import (
	"testing"

	"github.com/google/nftables"
)

// Unit tests for the expression parser to boost coverage without
// needing acceptance tests (no network namespace required).

func mustParse(t *testing.T, expr string, family nftables.TableFamily) {
	t.Helper()
	result, err := parseRuleExpression(expr, family)
	if err != nil {
		t.Fatalf("parseRuleExpression(%q) error: %v", expr, err)
	}
	if len(result) == 0 {
		t.Fatalf("parseRuleExpression(%q) returned empty result", expr)
	}
}

func mustFail(t *testing.T, expr string, family nftables.TableFamily) {
	t.Helper()
	_, err := parseRuleExpression(expr, family)
	if err == nil {
		t.Fatalf("parseRuleExpression(%q) should have failed", expr)
	}
}

// --- Verdict tests ---
func TestParser_verdicts(t *testing.T) {
	mustParse(t, "accept", nftables.TableFamilyIPv4)
	mustParse(t, "drop", nftables.TableFamilyIPv4)
	mustParse(t, "return", nftables.TableFamilyIPv4)
	mustParse(t, "continue", nftables.TableFamilyIPv4)
	mustParse(t, "jump mychain", nftables.TableFamilyIPv4)
	mustParse(t, "goto mychain", nftables.TableFamilyIPv4)
}

func TestParser_verdictErrors(t *testing.T) {
	mustFail(t, "jump", nftables.TableFamilyIPv4)
	mustFail(t, "goto", nftables.TableFamilyIPv4)
	mustFail(t, "", nftables.TableFamilyIPv4)
	mustFail(t, "unknownverdict", nftables.TableFamilyIPv4)
}

// --- IP match ---
func TestParser_ipAllFields(t *testing.T) {
	mustParse(t, "ip saddr 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip daddr 10.0.0.0/8 drop", nftables.TableFamilyIPv4)
	mustParse(t, "ip saddr 192.168.0.0/24 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip protocol tcp accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip ttl 64 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip dscp 0x2e accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip length 1500 drop", nftables.TableFamilyIPv4)
	mustParse(t, "ip id 1234 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip frag-off 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip version 4 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip hdrlength 5 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip checksum 0x1234 accept", nftables.TableFamilyIPv4)
	// Negation
	mustParse(t, "ip saddr != 10.0.0.1 drop", nftables.TableFamilyIPv4)
	mustParse(t, "ip daddr != 10.0.0.0/8 accept", nftables.TableFamilyIPv4)
}

func TestParser_ipErrors(t *testing.T) {
	mustFail(t, "ip saddr", nftables.TableFamilyIPv4)
	mustFail(t, "ip", nftables.TableFamilyIPv4)
	mustFail(t, "ip unknown_field 1 accept", nftables.TableFamilyIPv4)
	mustFail(t, "ip saddr not_an_ip accept", nftables.TableFamilyIPv4)
	mustFail(t, "ip ttl not_a_number accept", nftables.TableFamilyIPv4)
}

// --- IP6 match ---
func TestParser_ip6AllFields(t *testing.T) {
	mustParse(t, "ip6 saddr ::1 accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 daddr fd00::/8 drop", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 nexthdr tcp accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 hoplimit 255 accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 flowlabel 0x12345 accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 length 100 accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 version 6 accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 dscp 0x2e accept", nftables.TableFamilyIPv6)
	mustParse(t, "ip6 saddr != ::1 drop", nftables.TableFamilyIPv6)
}

func TestParser_ip6Errors(t *testing.T) {
	mustFail(t, "ip6 saddr", nftables.TableFamilyIPv6)
	mustFail(t, "ip6", nftables.TableFamilyIPv6)
	mustFail(t, "ip6 unknown 1 accept", nftables.TableFamilyIPv6)
}

// --- TCP match ---
func TestParser_tcpAllFields(t *testing.T) {
	mustParse(t, "tcp sport 80 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp dport 443 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp flags syn accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp flags syn|ack accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp flags fin|rst|psh|ack|urg|ecn|cwr accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp sequence 12345 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp ackseq 12345 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp doff 5 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp window 65535 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp checksum 0x1234 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp urgptr 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp dport != 22 accept", nftables.TableFamilyIPv4)
}

func TestParser_tcpErrors(t *testing.T) {
	mustFail(t, "tcp", nftables.TableFamilyIPv4)
	mustFail(t, "tcp dport", nftables.TableFamilyIPv4)
	mustFail(t, "tcp unknown 1 accept", nftables.TableFamilyIPv4)
	mustFail(t, "tcp flags invalid_flag accept", nftables.TableFamilyIPv4)
}

// --- UDP match ---
func TestParser_udpAllFields(t *testing.T) {
	mustParse(t, "udp sport 53 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udp dport 53 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udp length 100 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udp checksum 0x1234 accept", nftables.TableFamilyIPv4)
}

func TestParser_udpErrors(t *testing.T) {
	mustFail(t, "udp", nftables.TableFamilyIPv4)
	mustFail(t, "udp unknown 1 accept", nftables.TableFamilyIPv4)
}

// --- ICMP match ---
func TestParser_icmpAllTypes(t *testing.T) {
	types := []string{
		"echo-reply", "destination-unreachable", "source-quench", "redirect",
		"echo-request", "router-advertisement", "router-solicitation",
		"time-exceeded", "parameter-problem", "timestamp-request",
		"timestamp-reply", "info-request", "info-reply",
		"address-mask-request", "address-mask-reply",
	}
	for _, typ := range types {
		mustParse(t, "icmp type "+typ+" accept", nftables.TableFamilyIPv4)
	}
}

func TestParser_icmpAllFields(t *testing.T) {
	mustParse(t, "icmp type echo-request accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp code 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp checksum 0x1234 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp id 1234 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp sequence 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp mtu 1500 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp gateway 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp type 8 accept", nftables.TableFamilyIPv4) // numeric
}

// --- ICMPv6 match ---
func TestParser_icmpv6AllTypes(t *testing.T) {
	types := []string{
		"destination-unreachable", "packet-too-big", "time-exceeded",
		"parameter-problem", "echo-request", "echo-reply",
		"mld-listener-query", "mld-listener-report", "mld-listener-done",
		"nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit",
		"nd-neighbor-advert", "nd-redirect",
	}
	for _, typ := range types {
		mustParse(t, "icmpv6 type "+typ+" accept", nftables.TableFamilyIPv6)
	}
}

func TestParser_icmpv6AllFields(t *testing.T) {
	mustParse(t, "icmpv6 code 0 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 checksum 0x1234 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 id 1234 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 sequence 1 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 mtu 1500 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 max-delay 1000 accept", nftables.TableFamilyIPv6)
	mustParse(t, "icmpv6 type 128 accept", nftables.TableFamilyIPv6) // numeric
}

// --- Ethernet match ---
func TestParser_etherAllFields(t *testing.T) {
	mustParse(t, "ether saddr 00:11:22:33:44:55 accept", nftables.TableFamilyBridge)
	mustParse(t, "ether daddr ff:ff:ff:ff:ff:ff drop", nftables.TableFamilyBridge)
	mustParse(t, "ether type 0x0800 accept", nftables.TableFamilyBridge)
	mustParse(t, "ether saddr != 00:11:22:33:44:55 drop", nftables.TableFamilyBridge)
}

func TestParser_etherErrors(t *testing.T) {
	mustFail(t, "ether", nftables.TableFamilyBridge)
	mustFail(t, "ether saddr", nftables.TableFamilyBridge)
	mustFail(t, "ether unknown 1 accept", nftables.TableFamilyBridge)
	mustFail(t, "ether saddr not_a_mac accept", nftables.TableFamilyBridge)
}

// --- VLAN match ---
func TestParser_vlanAllFields(t *testing.T) {
	mustParse(t, "vlan id 100 accept", nftables.TableFamilyBridge)
	mustParse(t, "vlan cfi 0 accept", nftables.TableFamilyBridge)
	mustParse(t, "vlan pcp 5 accept", nftables.TableFamilyBridge)
}

func TestParser_vlanErrors(t *testing.T) {
	mustFail(t, "vlan", nftables.TableFamilyBridge)
	mustFail(t, "vlan unknown 1 accept", nftables.TableFamilyBridge)
}

// --- ARP match ---
func TestParser_arpAllFields(t *testing.T) {
	mustParse(t, "arp htype 1 accept", nftables.TableFamilyARP)
	mustParse(t, "arp ptype 0x0800 accept", nftables.TableFamilyARP)
	mustParse(t, "arp hlen 6 accept", nftables.TableFamilyARP)
	mustParse(t, "arp plen 4 accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation request accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation reply accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation rrequest accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation rreply accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation inrequest accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation inreply accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation nak accept", nftables.TableFamilyARP)
	mustParse(t, "arp operation 1 accept", nftables.TableFamilyARP) // numeric
}

func TestParser_arpErrors(t *testing.T) {
	mustFail(t, "arp", nftables.TableFamilyARP)
	mustFail(t, "arp unknown 1 accept", nftables.TableFamilyARP)
	mustFail(t, "arp operation bogus accept", nftables.TableFamilyARP)
}

// --- SCTP/DCCP/ESP/AH/COMP/UDPLite ---
func TestParser_sctpAllFields(t *testing.T) {
	mustParse(t, "sctp sport 5060 accept", nftables.TableFamilyIPv4)
	mustParse(t, "sctp dport 5060 accept", nftables.TableFamilyIPv4)
	mustParse(t, "sctp vtag 12345 accept", nftables.TableFamilyIPv4)
	mustParse(t, "sctp checksum 0x1234 accept", nftables.TableFamilyIPv4)
}

func TestParser_dccpAllFields(t *testing.T) {
	mustParse(t, "dccp sport 5060 accept", nftables.TableFamilyIPv4)
	mustParse(t, "dccp dport 5060 accept", nftables.TableFamilyIPv4)
	types := []string{"request", "response", "data", "ack", "dataack", "closereq", "close", "reset", "sync", "syncack"}
	for _, typ := range types {
		mustParse(t, "dccp type "+typ+" accept", nftables.TableFamilyIPv4)
	}
	mustParse(t, "dccp type 0 accept", nftables.TableFamilyIPv4) // numeric
}

func TestParser_espAllFields(t *testing.T) {
	mustParse(t, "esp spi 0x100 accept", nftables.TableFamilyIPv4)
	mustParse(t, "esp sequence 12345 accept", nftables.TableFamilyIPv4)
}

func TestParser_ahAllFields(t *testing.T) {
	mustParse(t, "ah hdrlength 4 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ah reserved 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ah spi 0x200 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ah sequence 12345 accept", nftables.TableFamilyIPv4)
}

func TestParser_compAllFields(t *testing.T) {
	mustParse(t, "comp nexthdr tcp accept", nftables.TableFamilyIPv4)
	mustParse(t, "comp flags 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "comp cpi 1 accept", nftables.TableFamilyIPv4)
}

func TestParser_udpliteAllFields(t *testing.T) {
	mustParse(t, "udplite sport 5060 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udplite dport 5060 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udplite checksum 0x1234 accept", nftables.TableFamilyIPv4)
}

// --- Meta match ---
func TestParser_metaAllFields(t *testing.T) {
	mustParse(t, "meta iif 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta iifname eth0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta iiftype 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta iifkind bridge accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta iifgroup 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta oif 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta oifname lo accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta oiftype 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta oifkind veth accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta oifgroup 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta length 1500 drop", nftables.TableFamilyIPv4)
	mustParse(t, "meta protocol 0x0800 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta nfproto ipv4 accept", nftables.TableFamilyINet)
	mustParse(t, "meta nfproto ipv6 accept", nftables.TableFamilyINet)
	mustParse(t, "meta nfproto ip accept", nftables.TableFamilyINet)
	mustParse(t, "meta nfproto ip6 accept", nftables.TableFamilyINet)
	mustParse(t, "meta l4proto tcp accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta mark 0x42 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta priority 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta skuid 1000 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta skgid 1000 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta pkttype host accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta pkttype broadcast drop", nftables.TableFamilyIPv4)
	mustParse(t, "meta pkttype multicast drop", nftables.TableFamilyIPv4)
	mustParse(t, "meta pkttype other drop", nftables.TableFamilyIPv4)
	mustParse(t, "meta cpu 0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta cgroup 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "meta nftrace 1 accept", nftables.TableFamilyIPv4)
}

func TestParser_metaSet(t *testing.T) {
	mustParse(t, "meta mark set 0x1", nftables.TableFamilyIPv4)
	mustParse(t, "meta priority set 0x10", nftables.TableFamilyIPv4)
	mustParse(t, "meta nftrace set 1", nftables.TableFamilyIPv4)
	mustParse(t, "meta pkttype set host", nftables.TableFamilyIPv4)
}

func TestParser_metaSetErrors(t *testing.T) {
	mustFail(t, "meta unknown set 1", nftables.TableFamilyIPv4)
}

func TestParser_metaShorthand(t *testing.T) {
	mustParse(t, "iifname lo accept", nftables.TableFamilyIPv4)
	mustParse(t, "oifname eth0 accept", nftables.TableFamilyIPv4)
	mustParse(t, "iif 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "oif 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "iiftype 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "oiftype 1 accept", nftables.TableFamilyIPv4)
}

// --- CT match ---
func TestParser_ctAllFields(t *testing.T) {
	mustParse(t, "ct state new accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct state established,related accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct state invalid drop", nftables.TableFamilyIPv4)
	mustParse(t, "ct state untracked accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct direction original accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct direction reply accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status expected accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status seen-reply accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status assured accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status confirmed accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status snat accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status dnat accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct status dying accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct mark 0x1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct zone 1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct l3proto ip accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct protocol tcp accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct saddr 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct daddr 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct proto-src 80 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct proto-dst 80 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct reply saddr 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct original daddr 10.0.0.1 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct reply proto-src 80 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct original proto-dst 80 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct helper ftp accept", nftables.TableFamilyIPv4)
}

func TestParser_ctSet(t *testing.T) {
	mustParse(t, "ct mark set 0x42", nftables.TableFamilyIPv4)
}

func TestParser_ctErrors(t *testing.T) {
	mustFail(t, "ct", nftables.TableFamilyIPv4)
	mustFail(t, "ct unknown 1 accept", nftables.TableFamilyIPv4)
	mustFail(t, "ct state bogus accept", nftables.TableFamilyIPv4)
	mustFail(t, "ct status bogus accept", nftables.TableFamilyIPv4)
	mustFail(t, "ct direction bogus accept", nftables.TableFamilyIPv4)
}

// --- NAT ---
func TestParser_nat(t *testing.T) {
	mustParse(t, "snat to 192.168.1.1", nftables.TableFamilyIPv4)
	mustParse(t, "snat to 192.168.1.1:1024-65535", nftables.TableFamilyIPv4)
	mustParse(t, "dnat to 10.0.0.1:8080", nftables.TableFamilyIPv4)
	mustParse(t, "dnat to 10.0.0.1", nftables.TableFamilyIPv4)
	mustParse(t, "masquerade", nftables.TableFamilyIPv4)
	mustParse(t, "masquerade random", nftables.TableFamilyIPv4)
	mustParse(t, "masquerade fully-random", nftables.TableFamilyIPv4)
	mustParse(t, "masquerade persistent", nftables.TableFamilyIPv4)
	mustParse(t, "masquerade to :1024-65535", nftables.TableFamilyIPv4)
	mustParse(t, "redirect to :8080", nftables.TableFamilyIPv4)
	mustParse(t, "redirect to :8080-9090", nftables.TableFamilyIPv4)
	mustParse(t, "redirect", nftables.TableFamilyIPv4)
}

func TestParser_natErrors(t *testing.T) {
	mustFail(t, "snat to bogus", nftables.TableFamilyIPv4)
	mustFail(t, "dnat to bogus", nftables.TableFamilyIPv4)
	mustFail(t, "snat", nftables.TableFamilyIPv4)
	mustFail(t, "dnat", nftables.TableFamilyIPv4)
}

// --- Counter, limit, log, reject, notrack, queue ---
func TestParser_counter(t *testing.T) {
	mustParse(t, "counter", nftables.TableFamilyIPv4)
}

func TestParser_limitAllVariations(t *testing.T) {
	mustParse(t, "limit rate 10/second accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 100/minute accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 1000/hour accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 10000/day accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 100000/week accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate over 100/second drop", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 10/second burst 5 accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 10 second accept", nftables.TableFamilyIPv4) // alternate syntax
	mustParse(t, "limit rate 10 mbytes/second accept", nftables.TableFamilyIPv4) // byte rate
	mustParse(t, "limit rate 10 kbytes/second accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 10 bytes/second accept", nftables.TableFamilyIPv4)
	mustParse(t, "limit rate 10/second burst 5 packets accept", nftables.TableFamilyIPv4)
}

func TestParser_logAllLevels(t *testing.T) {
	mustParse(t, "log", nftables.TableFamilyIPv4)
	mustParse(t, "log prefix \"TEST:\"", nftables.TableFamilyIPv4)
	mustParse(t, "log level emerg", nftables.TableFamilyIPv4)
	mustParse(t, "log level alert", nftables.TableFamilyIPv4)
	mustParse(t, "log level crit", nftables.TableFamilyIPv4)
	mustParse(t, "log level err", nftables.TableFamilyIPv4)
	mustParse(t, "log level warn", nftables.TableFamilyIPv4)
	mustParse(t, "log level warning", nftables.TableFamilyIPv4) // alias
	mustParse(t, "log level notice", nftables.TableFamilyIPv4)
	mustParse(t, "log level info", nftables.TableFamilyIPv4)
	mustParse(t, "log level debug", nftables.TableFamilyIPv4)
	mustParse(t, "log group 1", nftables.TableFamilyIPv4)
	mustParse(t, "log snaplen 128", nftables.TableFamilyIPv4)
	mustParse(t, "log queue-threshold 10", nftables.TableFamilyIPv4)
	mustParse(t, "log prefix \"TEST:\" level info", nftables.TableFamilyIPv4)
}

func TestParser_rejectAllVariations(t *testing.T) {
	mustParse(t, "reject", nftables.TableFamilyIPv4)
	mustParse(t, "reject", nftables.TableFamilyIPv6)
	mustParse(t, "reject", nftables.TableFamilyINet)
	mustParse(t, "reject with tcp reset", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type port-unreachable", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type host-unreachable", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type net-unreachable", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type prot-unreachable", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type net-prohibited", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type host-prohibited", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmp type admin-prohibited", nftables.TableFamilyIPv4)
	mustParse(t, "reject with icmpv6 type no-route", nftables.TableFamilyIPv6)
	mustParse(t, "reject with icmpv6 type admin-prohibited", nftables.TableFamilyIPv6)
	mustParse(t, "reject with icmpv6 type addr-unreachable", nftables.TableFamilyIPv6)
	mustParse(t, "reject with icmpv6 type port-unreachable", nftables.TableFamilyIPv6)
	mustParse(t, "reject with icmpx type port-unreachable", nftables.TableFamilyINet)
	mustParse(t, "reject with icmpx type admin-prohibited", nftables.TableFamilyINet)
	mustParse(t, "reject with icmpx type no-route", nftables.TableFamilyINet)
	mustParse(t, "reject with icmpx type host-unreachable", nftables.TableFamilyINet)
}

func TestParser_notrack(t *testing.T) {
	mustParse(t, "notrack", nftables.TableFamilyIPv4)
}

func TestParser_queueAllVariations(t *testing.T) {
	mustParse(t, "queue", nftables.TableFamilyIPv4)
	mustParse(t, "queue num 1", nftables.TableFamilyIPv4)
	mustParse(t, "queue bypass", nftables.TableFamilyIPv4)
	mustParse(t, "queue fanout", nftables.TableFamilyIPv4)
	mustParse(t, "queue num 1 bypass fanout", nftables.TableFamilyIPv4)
}

// --- Mark ---
func TestParser_markSet(t *testing.T) {
	mustParse(t, "mark set 0x1", nftables.TableFamilyIPv4)
	mustParse(t, "mark set 42", nftables.TableFamilyIPv4)
}

// --- Flow offload ---
func TestParser_flowOffload(t *testing.T) {
	mustParse(t, "flow add @myft", nftables.TableFamilyIPv4)
}

// --- Fib ---
func TestParser_fib(t *testing.T) {
	mustParse(t, "fib daddr type != 0 accept", nftables.TableFamilyIPv4)
}

// --- Dup ---
func TestParser_dup(t *testing.T) {
	mustParse(t, "dup to 10.0.0.1", nftables.TableFamilyIPv4)
	mustParse(t, "dup to 10.0.0.1 device 1", nftables.TableFamilyIPv4)
}

// --- Protocol parsing ---
func TestParser_protocolNames(t *testing.T) {
	protos := []string{"tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre", "esp", "ah", "comp", "udplite", "ipip", "ipv6"}
	for _, p := range protos {
		mustParse(t, "ip protocol "+p+" accept", nftables.TableFamilyIPv4)
	}
	mustParse(t, "ip protocol 6 accept", nftables.TableFamilyIPv4) // numeric
}

// --- Combined expressions ---
func TestParser_combinedExpressions(t *testing.T) {
	mustParse(t, "ip saddr 10.0.0.0/8 tcp dport 22 accept", nftables.TableFamilyIPv4)
	mustParse(t, "ct state established,related accept", nftables.TableFamilyIPv4)
	mustParse(t, "iifname lo accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp dport 80 counter log prefix \"HTTP:\" accept", nftables.TableFamilyIPv4)
	mustParse(t, "ip saddr 192.168.1.0/24 tcp dport 443 ct state new counter accept", nftables.TableFamilyIPv4)
	mustParse(t, "tcp dport 22 limit rate 10/second burst 5 accept", nftables.TableFamilyIPv4)
	mustParse(t, "udp dport 53 counter accept", nftables.TableFamilyIPv4)
	mustParse(t, "icmp type echo-request limit rate 1/second accept", nftables.TableFamilyIPv4)
}

// --- Tokenizer ---
func TestParser_tokenizerBraces(t *testing.T) {
	tokens := tokenize("tcp dport {80, 443} accept")
	if len(tokens) != 4 {
		t.Fatalf("expected 4 tokens, got %d: %v", len(tokens), tokens)
	}
	if tokens[2] != "{80, 443}" {
		t.Fatalf("expected brace token, got %q", tokens[2])
	}
}

// --- parseFamily ---
func TestParser_parseFamily(t *testing.T) {
	cases := []struct{ input string; valid bool }{
		{"ip", true}, {"ipv4", true}, {"ip6", true}, {"ipv6", true},
		{"inet", true}, {"arp", true}, {"bridge", true}, {"netdev", true},
		{"bogus", false},
	}
	for _, tc := range cases {
		_, err := parseFamily(tc.input)
		if tc.valid && err != nil {
			t.Errorf("parseFamily(%q) should succeed, got: %v", tc.input, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("parseFamily(%q) should fail", tc.input)
		}
	}
}
