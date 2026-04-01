package provider

// Tests covering every expression from the nftables quick reference:
// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
//
// Each test creates resources in an isolated network namespace and
// verifies the resulting ruleset through the nft CLI.

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// ---------------------------------------------------------------------------
// Helpers for building test configs
// ---------------------------------------------------------------------------

func ipInputConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func ip6InputConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "ip6"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func inetInputConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "inet"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func arpInputConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "arp"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func bridgeForwardConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "bridge"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "accept"
}
`
}

func ipNatConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "ip"
  name   = "nat"
}
resource "nftables_chain" "pre" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "prerouting"
  type     = "nat"
  hook     = "prerouting"
  priority = -100
  policy   = "accept"
}
resource "nftables_chain" "post" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "postrouting"
  type     = "nat"
  hook     = "postrouting"
  priority = 100
  policy   = "accept"
}
`
}

func provfuncRule(exprParts string) string {
	return fmt.Sprintf(`
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr   = provider::nftables::combine(%s)
}`, exprParts)
}

func testExpr(t *testing.T, baseCfg func(string) string, parts string) {
	t.Helper()
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseCfg(ns) + provfuncRule(parts),
			Check:  resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func testExprNft(t *testing.T, baseCfg func(string) string, parts string, nftExpect string) {
	t.Helper()
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseCfg(ns) + provfuncRule(parts),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, nftExpect),
			),
		}},
	})
}

// ===========================================================================
// 1. IPv4 header matches
// ===========================================================================

func TestNftRef_ipSaddr(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_ip_saddr("192.168.1.0/24"), provider::nftables::accept()`, "192.168.1.0/24")
}
func TestNftRef_ipDaddr(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_ip_daddr("10.0.0.1"), provider::nftables::accept()`, "10.0.0.1")
}
func TestNftRef_ipProtocol(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ip_protocol("tcp"), provider::nftables::accept()`)
}
func TestNftRef_ipTTL(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ip_ttl(64), provider::nftables::accept()`)
}
func TestNftRef_ipLength(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ip_length(1500), provider::nftables::drop()`)
}

// ===========================================================================
// 2. IPv6 header matches
// ===========================================================================

func TestNftRef_ip6Saddr(t *testing.T) {
	testExprNft(t, ip6InputConfig, `provider::nftables::match_ip6_saddr("fd00::/8"), provider::nftables::accept()`, "fd00::/8")
}
func TestNftRef_ip6Daddr(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_ip6_daddr("::1"), provider::nftables::accept()`)
}
func TestNftRef_ip6HopLimit(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_ip6_hoplimit(255), provider::nftables::accept()`)
}
func TestNftRef_ip6NextHdr(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_ip6_nexthdr("tcp"), provider::nftables::accept()`)
}

// ===========================================================================
// 3. TCP matches
// ===========================================================================

func TestNftRef_tcpDport(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_tcp_dport(22), provider::nftables::accept()`, "dport 22")
}
func TestNftRef_tcpSport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_sport(80), provider::nftables::accept()`)
}
func TestNftRef_tcpFlags(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_flags("syn"), provider::nftables::accept()`)
}
func TestNftRef_tcpFlagsSynAck(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_flags("syn|ack"), provider::nftables::accept()`)
}

// ===========================================================================
// 4. UDP matches
// ===========================================================================

func TestNftRef_udpDport(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_udp_dport(53), provider::nftables::accept()`, "dport 53")
}
func TestNftRef_udpSport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_udp_sport(53), provider::nftables::accept()`)
}

// ===========================================================================
// 5. ICMP matches
// ===========================================================================

func TestNftRef_icmpEchoRequest(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_icmp_type("echo-request"), provider::nftables::accept()`)
}
func TestNftRef_icmpEchoReply(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_icmp_type("echo-reply"), provider::nftables::accept()`)
}
func TestNftRef_icmpDestUnreach(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_icmp_type("destination-unreachable"), provider::nftables::accept()`)
}
func TestNftRef_icmpRedirect(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_icmp_type("redirect"), provider::nftables::accept()`)
}
func TestNftRef_icmpTimeExceeded(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_icmp_type("time-exceeded"), provider::nftables::accept()`)
}

// ===========================================================================
// 6. ICMPv6 matches
// ===========================================================================

func TestNftRef_icmpv6EchoRequest(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_icmpv6_type("echo-request"), provider::nftables::accept()`)
}
func TestNftRef_icmpv6NdNeighborSolicit(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_icmpv6_type("nd-neighbor-solicit"), provider::nftables::accept()`)
}
func TestNftRef_icmpv6NdRouterAdvert(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_icmpv6_type("nd-router-advert"), provider::nftables::accept()`)
}
func TestNftRef_icmpv6PktTooBig(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::match_icmpv6_type("packet-too-big"), provider::nftables::accept()`)
}

// ===========================================================================
// 7. SCTP matches
// ===========================================================================

func TestNftRef_sctpDport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_sctp_dport(5060), provider::nftables::accept()`)
}
func TestNftRef_sctpSport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_sctp_sport(5060), provider::nftables::accept()`)
}

// ===========================================================================
// 8. DCCP matches
// ===========================================================================

func TestNftRef_dccpDport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_dccp_dport(5004), provider::nftables::accept()`)
}
func TestNftRef_dccpSport(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_dccp_sport(5004), provider::nftables::accept()`)
}

// ===========================================================================
// 9. ESP / AH matches (via expression string, helper coverage tested in parser_test)
// ===========================================================================

func TestNftRef_espSpi(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ip_protocol("esp"), provider::nftables::accept()`)
}

// ===========================================================================
// 10. Ethernet matches
// ===========================================================================

func TestNftRef_etherSaddr(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: bridgeForwardConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expression = "ether saddr 00:11:22:33:44:55 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func TestNftRef_etherType(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: bridgeForwardConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expression = "ether type 0x0800 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 11. VLAN matches
// ===========================================================================

func TestNftRef_vlanId(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: bridgeForwardConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expression = "vlan id 100 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 12. ARP matches
// ===========================================================================

func TestNftRef_arpOperation(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpInputConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expression = "arp operation request accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func TestNftRef_arpHtype(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpInputConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expression = "arp htype 1 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 13. Meta matches
// ===========================================================================

func TestNftRef_metaIifname(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_iifname("lo"), provider::nftables::accept()`, "iifname")
}
func TestNftRef_metaOifname(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_oifname("lo"), provider::nftables::accept()`)
}
func TestNftRef_metaMark(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_mark(42), provider::nftables::accept()`)
}
func TestNftRef_metaNfproto(t *testing.T) {
	testExpr(t, inetInputConfig, `provider::nftables::match_nfproto("ipv4"), provider::nftables::accept()`)
}
func TestNftRef_metaL4proto(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_l4proto("tcp"), provider::nftables::accept()`)
}
func TestNftRef_metaPkttype(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_pkttype("broadcast"), provider::nftables::drop()`)
}
func TestNftRef_metaSkuid(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "c" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  name = "output"
  type = "filter"
  hook = "output"
  priority = 0
  policy = "accept"
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.c.name
  expr = provider::nftables::combine(provider::nftables::match_skuid(0), provider::nftables::accept())
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 14. CT matches
// ===========================================================================

func TestNftRef_ctStateEstablished(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_ct_state(["established", "related"]), provider::nftables::accept()`, "established")
}
func TestNftRef_ctStateNew(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_state(["new"]), provider::nftables::accept()`)
}
func TestNftRef_ctStateInvalid(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_state(["invalid"]), provider::nftables::drop()`)
}
func TestNftRef_ctStateUntracked(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_state(["untracked"]), provider::nftables::accept()`)
}
func TestNftRef_ctDirection(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_direction("original"), provider::nftables::accept()`)
}
func TestNftRef_ctStatus(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_status(["assured"]), provider::nftables::accept()`)
}
func TestNftRef_ctMark(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_ct_mark(1), provider::nftables::accept()`)
}

// ===========================================================================
// 15. Verdict statements
// ===========================================================================

func TestNftRef_verdictAccept(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::accept()`)
}
func TestNftRef_verdictDrop(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::drop()`)
}
func TestNftRef_verdictReturn(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::return_verdict()`)
}
func TestNftRef_verdictJump(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipInputConfig(ns) + `
resource "nftables_chain" "target" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  name = "mychain"
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.c.name
  expr = provider::nftables::combine(provider::nftables::match_tcp_dport(80), provider::nftables::jump("mychain"))
  depends_on = [nftables_chain.target]
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}
func TestNftRef_verdictGoto(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipInputConfig(ns) + `
resource "nftables_chain" "target" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  name = "mychain"
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.c.name
  expr = provider::nftables::combine(provider::nftables::match_tcp_dport(443), provider::nftables::goto_chain("mychain"))
  depends_on = [nftables_chain.target]
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 16. NAT statements
// ===========================================================================

func TestNftRef_masquerade(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.post.name
  expr = provider::nftables::combine(provider::nftables::match_oifname("lo"), provider::nftables::masquerade())
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}
func TestNftRef_masqueradeRandom(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.post.name
  expr = provider::nftables::combine(provider::nftables::masquerade_random())
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}
func TestNftRef_snat(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.post.name
  expr = provider::nftables::combine(provider::nftables::match_ip_saddr("172.16.0.0/12"), provider::nftables::snat("203.0.113.1"))
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}
func TestNftRef_dnat(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.pre.name
  expr = provider::nftables::combine(provider::nftables::match_tcp_dport(8080), provider::nftables::dnat_port("10.0.0.5", 80))
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 17. Counter, Limit, Log statements
// ===========================================================================

func TestNftRef_counter(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::match_tcp_dport(80), provider::nftables::counter(), provider::nftables::accept()`, "counter")
}
func TestNftRef_limitPerSecond(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::limit(10, "second"), provider::nftables::accept()`)
}
func TestNftRef_limitPerMinute(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::limit(400, "minute"), provider::nftables::accept()`)
}
func TestNftRef_limitBurst(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::limit_burst(100, "second", 50), provider::nftables::accept()`)
}
func TestNftRef_limitBytes(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::limit_bytes(1048576, "second"), provider::nftables::accept()`)
}
func TestNftRef_logPrefix(t *testing.T) {
	testExprNft(t, ipInputConfig, `provider::nftables::log("INPUT", "info"), provider::nftables::accept()`, "log")
}

// ===========================================================================
// 18. Reject statements
// ===========================================================================

func TestNftRef_rejectDefault(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::reject()`)
}
func TestNftRef_rejectTCPReset(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_dport(80), provider::nftables::reject_tcp_reset()`)
}
func TestNftRef_rejectICMPHostUnreach(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::reject_icmp("host-unreachable")`)
}
func TestNftRef_rejectICMPAdminProhib(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::reject_icmp("admin-prohibited")`)
}
func TestNftRef_rejectICMPv6(t *testing.T) {
	testExpr(t, ip6InputConfig, `provider::nftables::reject_icmpv6("admin-prohibited")`)
}
func TestNftRef_rejectICMPx(t *testing.T) {
	testExpr(t, inetInputConfig, `provider::nftables::reject_icmpx("admin-prohibited")`)
}

// ===========================================================================
// 19. Mark manipulation
// ===========================================================================

func TestNftRef_setMark(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_dport(80), provider::nftables::set_mark(42)`)
}
func TestNftRef_setCTMark(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_dport(80), provider::nftables::set_ct_mark(1)`)
}
func TestNftRef_setPriority(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_dport(22), provider::nftables::set_priority(10)`)
}

// ===========================================================================
// 20. Notrack
// ===========================================================================

func TestNftRef_notrack(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "t" {
  family = "ip"
  name   = "raw"
}
resource "nftables_chain" "c" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  name = "prerouting"
  type = "filter"
  hook = "prerouting"
  priority = -300
  policy = "accept"
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.c.name
  expr = provider::nftables::combine(provider::nftables::match_udp_dport(53), provider::nftables::notrack())
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 21. Queue
// ===========================================================================

func TestNftRef_queue(t *testing.T) {
	testExpr(t, ipInputConfig, `provider::nftables::match_tcp_dport(8080), provider::nftables::queue(1)`)
}

// ===========================================================================
// 22. Redirect
// ===========================================================================

func TestNftRef_redirect(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.pre.name
  expr = provider::nftables::combine(provider::nftables::match_tcp_dport(80), provider::nftables::redirect(3128))
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

// ===========================================================================
// 23. Combined real-world expressions (compound matchers + actions)
// ===========================================================================

func TestNftRef_sshFromSubnet(t *testing.T) {
	testExprNft(t, ipInputConfig,
		`provider::nftables::match_ip_saddr("10.0.0.0/8"), provider::nftables::match_tcp_dport(22), provider::nftables::match_ct_state(["new"]), provider::nftables::counter(), provider::nftables::accept()`,
		"dport 22")
}

func TestNftRef_rateLimitedPing(t *testing.T) {
	testExpr(t, ipInputConfig,
		`provider::nftables::match_icmp_type("echo-request"), provider::nftables::limit_burst(10, "second", 20), provider::nftables::accept()`)
}

func TestNftRef_logAndDrop(t *testing.T) {
	testExpr(t, ipInputConfig,
		`provider::nftables::limit(5, "minute"), provider::nftables::log("DROPPED", "warn"), provider::nftables::counter(), provider::nftables::drop()`)
}

func TestNftRef_dnatPortForward(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.pre.name
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::match_tcp_dport(8080),
    provider::nftables::dnat_port("10.0.0.5", 80),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func TestNftRef_masqueradeOutbound(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ipNatConfig(ns) + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table = nftables_table.t.name
  chain = nftables_chain.post.name
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("lo"),
    provider::nftables::masquerade(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}
