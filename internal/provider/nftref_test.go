package provider

// Tests every canonical rule from the nftables quick reference:
// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
//
// For each rule, two subtests run, each in its own network namespace:
//
//   - "expression" — the rule body written as an `expression = "..."` string.
//   - "provfunc"   — the same rule built from provider-defined functions via
//                    `expr = provider::nftables::combine(...)`.
//
// Both variants apply the rule, then assert that the expected text appears in
// `nft list ruleset` output. Rules for which no provider function exists (ether,
// vlan, arp, ip dscp, ip6 flowlabel, …) are tested via the string form only.

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// ---------------------------------------------------------------------------
// Config scaffolding
// ---------------------------------------------------------------------------

type chainCfg struct {
	family, tableName, chain, chainType, hook string
	priority                                  int
}

var (
	cfgIPInput   = chainCfg{"ip", "filter", "input", "filter", "input", 0}
	cfgIPOutput  = chainCfg{"ip", "filter", "output", "filter", "output", 0}
	cfgIP6Input  = chainCfg{"ip6", "filter", "input", "filter", "input", 0}
	cfgInetInput = chainCfg{"inet", "filter", "input", "filter", "input", 0}
	cfgArpInput  = chainCfg{"arp", "filter", "input", "filter", "input", 0}
	cfgBridgeFwd = chainCfg{"bridge", "filter", "forward", "filter", "forward", 0}
	cfgIPNatPre  = chainCfg{"ip", "nat", "prerouting", "nat", "prerouting", -100}
	cfgIPNatPost = chainCfg{"ip", "nat", "postrouting", "nat", "postrouting", 100}
	cfgIPRawPre  = chainCfg{"ip", "raw", "prerouting", "filter", "prerouting", -300}
)

func base(ns string, c chainCfg) string {
	return testutils.ProviderConfig(ns) + fmt.Sprintf(`
resource "nftables_table" "t" {
  family = %q
  name   = %q
}
resource "nftables_chain" "c" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = %q
  type     = %q
  hook     = %q
  priority = %d
  policy   = "accept"
}
`, c.family, c.tableName, c.chain, c.chainType, c.hook, c.priority)
}

func strBody(expr string) string {
	return fmt.Sprintf(`
resource "nftables_rule" "r" {
  family     = nftables_table.t.family
  table      = nftables_table.t.name
  chain      = nftables_chain.c.name
  expression = %q
}
`, expr)
}

func fnBody(parts string) string {
	return fmt.Sprintf(`
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr   = provider::nftables::combine(%s)
}
`, parts)
}

// checkNftHas returns a TestCheckFunc that verifies every needle appears in
// `ip netns exec <ns> nft list ruleset` output. Captures ns by value.
func checkNftHas(ns string, needles ...string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		out, err := exec.Command("ip", "netns", "exec", ns, "nft", "list", "ruleset").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft list ruleset in %s: %v\n%s", ns, err, out)
		}
		text := string(out)
		for _, n := range needles {
			if !strings.Contains(text, n) {
				return fmt.Errorf("nft output missing %q; got:\n%s", n, text)
			}
		}
		return nil
	}
}

// testBoth runs two subtests — one per rule form — each in its own namespace,
// both verifying the rule appears in nft output. Pass fnParts="" to skip the
// provider-function variant for rules with no equivalent function.
func testBoth(t *testing.T, c chainCfg, strExpr, fnParts string, nftNeedles ...string) {
	t.Helper()
	if strExpr != "" {
		t.Run("expression", func(t *testing.T) {
			ns := testutils.CreateTestNamespace(t)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config: base(ns, c) + strBody(strExpr),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
						checkNftHas(ns, nftNeedles...),
					),
				}},
			})
		})
	}
	if fnParts != "" {
		t.Run("provfunc", func(t *testing.T) {
			ns := testutils.CreateTestNamespace(t)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config: base(ns, c) + fnBody(fnParts),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
						checkNftHas(ns, nftNeedles...),
					),
				}},
			})
		})
	}
}

// ===========================================================================
// IPv4 matches
// ===========================================================================

func TestNftRef_ipSaddr(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip saddr 192.168.2.0/24 accept",
		`provider::nftables::match_ip_saddr("192.168.2.0/24"), provider::nftables::accept()`,
		"192.168.2.0/24")
}

func TestNftRef_ipDaddr(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip daddr 10.0.0.1 accept",
		`provider::nftables::match_ip_daddr("10.0.0.1"), provider::nftables::accept()`,
		"10.0.0.1")
}

func TestNftRef_ipProtocol(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip protocol tcp accept",
		`provider::nftables::match_ip_protocol("tcp"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ipTTL(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip ttl 64 accept",
		`provider::nftables::match_ip_ttl(64), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ipLength(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip length 232 drop",
		`provider::nftables::match_ip_length(232), provider::nftables::drop()`,
		"drop")
}

func TestNftRef_ipDscp(t *testing.T) {
	// cs1 == DSCP value 8. The string parser accepts numeric DSCP only.
	testBoth(t, cfgIPInput,
		"ip dscp 8 accept",
		`provider::nftables::match_ip_dscp(8), provider::nftables::accept()`,
		"dscp")
}

func TestNftRef_ipId(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip id 22 accept",
		`provider::nftables::match_ip_id(22), provider::nftables::accept()`,
		"ip id 22")
}

func TestNftRef_ipVersion(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip version 4 accept",
		`provider::nftables::match_ip_version(4), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ipHdrLength(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip hdrlength 5 accept",
		`provider::nftables::match_ip_hdrlength(5), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// IPv6 matches
// ===========================================================================

func TestNftRef_ip6Saddr(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 saddr fd00::/8 accept",
		`provider::nftables::match_ip6_saddr("fd00::/8"), provider::nftables::accept()`,
		"fd00::/8")
}

func TestNftRef_ip6Daddr(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 daddr ::1 accept",
		`provider::nftables::match_ip6_daddr("::1"), provider::nftables::accept()`,
		"::1")
}

func TestNftRef_ip6HopLimit(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 hoplimit 255 accept",
		`provider::nftables::match_ip6_hoplimit(255), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ip6NextHdr(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 nexthdr tcp accept",
		`provider::nftables::match_ip6_nexthdr("tcp"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ip6FlowLabel(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 flowlabel 22 accept",
		`provider::nftables::match_ip6_flowlabel(22), provider::nftables::accept()`,
		"flowlabel")
}

func TestNftRef_ip6Length(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 length 100 accept",
		`provider::nftables::match_ip6_length(100), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ip6Version(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"ip6 version 6 accept",
		`provider::nftables::match_ip6_version(6), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// TCP matches
// ===========================================================================

func TestNftRef_tcpDport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 22 accept",
		`provider::nftables::match_tcp_dport(22), provider::nftables::accept()`,
		"dport 22")
}

func TestNftRef_tcpSport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp sport 80 accept",
		`provider::nftables::match_tcp_sport(80), provider::nftables::accept()`,
		"sport 80")
}

func TestNftRef_tcpFlags(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp flags syn accept",
		`provider::nftables::match_tcp_flags("syn"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_tcpSequence(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp sequence 22 accept",
		`provider::nftables::match_tcp_sequence(22), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_tcpWindow(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp window 100 accept",
		`provider::nftables::match_tcp_window(100), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// UDP matches
// ===========================================================================

func TestNftRef_udpDport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"udp dport 53 accept",
		`provider::nftables::match_udp_dport(53), provider::nftables::accept()`,
		"dport 53")
}

func TestNftRef_udpSport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"udp sport 53 accept",
		`provider::nftables::match_udp_sport(53), provider::nftables::accept()`,
		"sport 53")
}

func TestNftRef_udpLength(t *testing.T) {
	testBoth(t, cfgIPInput,
		"udp length 100 accept",
		`provider::nftables::match_udp_length(100), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// SCTP / DCCP matches
// ===========================================================================

func TestNftRef_sctpDport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"sctp dport 5060 accept",
		`provider::nftables::match_sctp_dport(5060), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_sctpSport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"sctp sport 5060 accept",
		`provider::nftables::match_sctp_sport(5060), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_dccpDport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"dccp dport 5004 accept",
		`provider::nftables::match_dccp_dport(5004), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_dccpSport(t *testing.T) {
	testBoth(t, cfgIPInput,
		"dccp sport 5004 accept",
		`provider::nftables::match_dccp_sport(5004), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// ICMP / ICMPv6 matches
// ===========================================================================

func TestNftRef_icmpEchoRequest(t *testing.T) {
	testBoth(t, cfgIPInput,
		"icmp type echo-request accept",
		`provider::nftables::match_icmp_type("echo-request"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpEchoReply(t *testing.T) {
	testBoth(t, cfgIPInput,
		"icmp type echo-reply accept",
		`provider::nftables::match_icmp_type("echo-reply"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpDestUnreach(t *testing.T) {
	testBoth(t, cfgIPInput,
		"icmp type destination-unreachable accept",
		`provider::nftables::match_icmp_type("destination-unreachable"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpTimeExceeded(t *testing.T) {
	testBoth(t, cfgIPInput,
		"icmp type time-exceeded accept",
		`provider::nftables::match_icmp_type("time-exceeded"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpv6EchoRequest(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"icmpv6 type echo-request accept",
		`provider::nftables::match_icmpv6_type("echo-request"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpv6NdNeighborSolicit(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"icmpv6 type nd-neighbor-solicit accept",
		`provider::nftables::match_icmpv6_type("nd-neighbor-solicit"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpv6NdRouterAdvert(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"icmpv6 type nd-router-advert accept",
		`provider::nftables::match_icmpv6_type("nd-router-advert"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_icmpv6PacketTooBig(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"icmpv6 type packet-too-big accept",
		`provider::nftables::match_icmpv6_type("packet-too-big"), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// Ethernet / VLAN / ARP — string form only (no provider functions)
// ===========================================================================

func TestNftRef_etherSaddr(t *testing.T) {
	testBoth(t, cfgBridgeFwd,
		"ether saddr 00:11:22:33:44:55 accept",
		`provider::nftables::match_ether_saddr("00:11:22:33:44:55"), provider::nftables::accept()`,
		"00:11:22:33:44:55")
}

func TestNftRef_etherType(t *testing.T) {
	// 0x0800 == IPv4 EtherType. The string parser requires the numeric form.
	testBoth(t, cfgBridgeFwd,
		"ether type 0x0800 accept",
		`provider::nftables::match_ether_type(2048), provider::nftables::accept()`,
		"ether type")
}

func TestNftRef_vlanId(t *testing.T) {
	testBoth(t, cfgBridgeFwd,
		"vlan id 100 accept",
		`provider::nftables::match_vlan_id(100), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_arpOperation(t *testing.T) {
	testBoth(t, cfgArpInput,
		"arp operation request accept",
		`provider::nftables::match_arp_operation("request"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_arpHtype(t *testing.T) {
	testBoth(t, cfgArpInput,
		"arp htype 1 accept",
		`provider::nftables::match_arp_htype(1), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// Meta matches
// ===========================================================================

func TestNftRef_metaIifname(t *testing.T) {
	testBoth(t, cfgIPInput,
		"iifname lo accept",
		`provider::nftables::match_iifname("lo"), provider::nftables::accept()`,
		`iifname "lo"`)
}

func TestNftRef_metaOifname(t *testing.T) {
	testBoth(t, cfgIPInput,
		"oifname lo accept",
		`provider::nftables::match_oifname("lo"), provider::nftables::accept()`,
		`oifname "lo"`)
}

func TestNftRef_metaMark(t *testing.T) {
	testBoth(t, cfgIPInput,
		"meta mark 42 accept",
		`provider::nftables::match_mark(42), provider::nftables::accept()`,
		"mark")
}

func TestNftRef_metaNfproto(t *testing.T) {
	testBoth(t, cfgInetInput,
		"meta nfproto ipv4 accept",
		`provider::nftables::match_nfproto("ipv4"), provider::nftables::accept()`,
		"nfproto ipv4")
}

func TestNftRef_metaL4proto(t *testing.T) {
	testBoth(t, cfgIPInput,
		"meta l4proto tcp accept",
		`provider::nftables::match_l4proto("tcp"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_metaPkttype(t *testing.T) {
	testBoth(t, cfgIPInput,
		"meta pkttype broadcast drop",
		`provider::nftables::match_pkttype("broadcast"), provider::nftables::drop()`,
		"drop")
}

func TestNftRef_metaSkuid(t *testing.T) {
	testBoth(t, cfgIPOutput,
		"meta skuid 0 accept",
		`provider::nftables::match_skuid(0), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_metaSkgid(t *testing.T) {
	testBoth(t, cfgIPOutput,
		"meta skgid 0 accept",
		`provider::nftables::match_skgid(0), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_metaLength(t *testing.T) {
	testBoth(t, cfgIPInput,
		"meta length 1000 accept",
		`provider::nftables::match_meta_length(1000), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_metaProtocol(t *testing.T) {
	// EtherType 0x0800 == IP. The string parser requires the numeric form.
	testBoth(t, cfgIPInput,
		"meta protocol 0x0800 accept",
		`provider::nftables::match_meta_protocol(2048), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// Connection tracking matches
// ===========================================================================

func TestNftRef_ctStateEstablished(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct state established,related accept",
		`provider::nftables::match_ct_state(["established", "related"]), provider::nftables::accept()`,
		"established")
}

func TestNftRef_ctStateNew(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct state new accept",
		`provider::nftables::match_ct_state(["new"]), provider::nftables::accept()`,
		"new")
}

func TestNftRef_ctStateInvalid(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct state invalid drop",
		`provider::nftables::match_ct_state(["invalid"]), provider::nftables::drop()`,
		"invalid")
}

func TestNftRef_ctStateUntracked(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct state untracked accept",
		`provider::nftables::match_ct_state(["untracked"]), provider::nftables::accept()`,
		"untracked")
}

func TestNftRef_ctDirection(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct direction original accept",
		`provider::nftables::match_ct_direction("original"), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ctStatus(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct status assured accept",
		`provider::nftables::match_ct_status(["assured"]), provider::nftables::accept()`,
		"accept")
}

func TestNftRef_ctMark(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ct mark 1 accept",
		`provider::nftables::match_ct_mark(1), provider::nftables::accept()`,
		"accept")
}

// ===========================================================================
// Verdicts
// ===========================================================================

func TestNftRef_verdictAccept(t *testing.T) {
	testBoth(t, cfgIPInput, "accept", `provider::nftables::accept()`, "accept")
}

func TestNftRef_verdictDrop(t *testing.T) {
	testBoth(t, cfgIPInput, "drop", `provider::nftables::drop()`, "drop")
}

func TestNftRef_verdictReturn(t *testing.T) {
	testBoth(t, cfgIPInput, "return", `provider::nftables::return_verdict()`, "return")
}

func TestNftRef_verdictJump(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	targetChain := `
resource "nftables_chain" "target" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  name   = "mychain"
}
`
	t.Run("expression", func(t *testing.T) {
		ns := testutils.CreateTestNamespace(t)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{{
				Config: base(ns, cfgIPInput) + targetChain + `
resource "nftables_rule" "r" {
  family     = nftables_table.t.family
  table      = nftables_table.t.name
  chain      = nftables_chain.c.name
  expression = "tcp dport 80 jump mychain"
  depends_on = [nftables_chain.target]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
					checkNftHas(ns, "jump mychain"),
				),
			}},
		})
	})
	t.Run("provfunc", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{{
				Config: base(ns, cfgIPInput) + targetChain + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::jump("mychain"),
  )
  depends_on = [nftables_chain.target]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
					checkNftHas(ns, "jump mychain"),
				),
			}},
		})
	})
}

func TestNftRef_verdictGoto(t *testing.T) {
	targetChain := `
resource "nftables_chain" "target" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  name   = "mychain"
}
`
	t.Run("expression", func(t *testing.T) {
		ns := testutils.CreateTestNamespace(t)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{{
				Config: base(ns, cfgIPInput) + targetChain + `
resource "nftables_rule" "r" {
  family     = nftables_table.t.family
  table      = nftables_table.t.name
  chain      = nftables_chain.c.name
  expression = "tcp dport 443 goto mychain"
  depends_on = [nftables_chain.target]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
					checkNftHas(ns, "goto mychain"),
				),
			}},
		})
	})
	t.Run("provfunc", func(t *testing.T) {
		ns := testutils.CreateTestNamespace(t)
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{{
				Config: base(ns, cfgIPInput) + targetChain + `
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::goto_chain("mychain"),
  )
  depends_on = [nftables_chain.target]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
					checkNftHas(ns, "goto mychain"),
				),
			}},
		})
	})
}

// ===========================================================================
// NAT statements
// ===========================================================================

func TestNftRef_masquerade(t *testing.T) {
	testBoth(t, cfgIPNatPost,
		"oifname lo masquerade",
		`provider::nftables::match_oifname("lo"), provider::nftables::masquerade()`,
		"masquerade")
}

func TestNftRef_masqueradeRandom(t *testing.T) {
	testBoth(t, cfgIPNatPost,
		"masquerade random",
		`provider::nftables::masquerade_random()`,
		"random")
}

func TestNftRef_snat(t *testing.T) {
	testBoth(t, cfgIPNatPost,
		"ip saddr 172.16.0.0/12 snat to 203.0.113.1",
		`provider::nftables::match_ip_saddr("172.16.0.0/12"), provider::nftables::snat("203.0.113.1")`,
		"203.0.113.1")
}

func TestNftRef_dnat(t *testing.T) {
	testBoth(t, cfgIPNatPre,
		"tcp dport 8080 dnat to 10.0.0.5:80",
		`provider::nftables::match_tcp_dport(8080), provider::nftables::dnat_port("10.0.0.5", 80)`,
		"10.0.0.5")
}

// ===========================================================================
// Counter, limit, log statements
// ===========================================================================

func TestNftRef_counter(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 80 counter accept",
		`provider::nftables::match_tcp_dport(80), provider::nftables::counter(), provider::nftables::accept()`,
		"counter")
}

func TestNftRef_limitPerSecond(t *testing.T) {
	testBoth(t, cfgIPInput,
		"limit rate 10/second accept",
		`provider::nftables::limit(10, "second"), provider::nftables::accept()`,
		"10/second")
}

func TestNftRef_limitPerMinute(t *testing.T) {
	testBoth(t, cfgIPInput,
		"limit rate 400/minute accept",
		`provider::nftables::limit(400, "minute"), provider::nftables::accept()`,
		"400/minute")
}

func TestNftRef_limitBurst(t *testing.T) {
	testBoth(t, cfgIPInput,
		"limit rate 100/second burst 50 packets accept",
		`provider::nftables::limit_burst(100, "second", 50), provider::nftables::accept()`,
		"burst")
}

func TestNftRef_limitBytes(t *testing.T) {
	testBoth(t, cfgIPInput,
		"limit rate 1048576 bytes/second accept",
		`provider::nftables::limit_bytes(1048576, "second"), provider::nftables::accept()`,
		"bytes/second")
}

func TestNftRef_logPrefix(t *testing.T) {
	testBoth(t, cfgIPInput,
		`log prefix "INPUT" accept`,
		`provider::nftables::log("INPUT", "info"), provider::nftables::accept()`,
		"log")
}

// ===========================================================================
// Reject statements
// ===========================================================================

func TestNftRef_rejectDefault(t *testing.T) {
	testBoth(t, cfgIPInput, "reject", `provider::nftables::reject()`, "reject")
}

func TestNftRef_rejectTCPReset(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 80 reject with tcp reset",
		`provider::nftables::match_tcp_dport(80), provider::nftables::reject_tcp_reset()`,
		"tcp reset")
}

func TestNftRef_rejectICMPHostUnreach(t *testing.T) {
	testBoth(t, cfgIPInput,
		"reject with icmp type host-unreachable",
		`provider::nftables::reject_icmp("host-unreachable")`,
		"host-unreachable")
}

func TestNftRef_rejectICMPAdminProhib(t *testing.T) {
	testBoth(t, cfgIPInput,
		"reject with icmp type admin-prohibited",
		`provider::nftables::reject_icmp("admin-prohibited")`,
		"admin-prohibited")
}

func TestNftRef_rejectICMPv6(t *testing.T) {
	testBoth(t, cfgIP6Input,
		"reject with icmpv6 type admin-prohibited",
		`provider::nftables::reject_icmpv6("admin-prohibited")`,
		"admin-prohibited")
}

func TestNftRef_rejectICMPx(t *testing.T) {
	testBoth(t, cfgInetInput,
		"reject with icmpx type admin-prohibited",
		`provider::nftables::reject_icmpx("admin-prohibited")`,
		"admin-prohibited")
}

// ===========================================================================
// Mark / priority manipulation
// ===========================================================================

func TestNftRef_setMark(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 80 meta mark set 42",
		`provider::nftables::match_tcp_dport(80), provider::nftables::set_mark(42)`,
		"mark set")
}

func TestNftRef_setCTMark(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 80 ct mark set 1",
		`provider::nftables::match_tcp_dport(80), provider::nftables::set_ct_mark(1)`,
		"ct mark set")
}

func TestNftRef_setPriority(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 22 meta priority set 10",
		`provider::nftables::match_tcp_dport(22), provider::nftables::set_priority(10)`,
		"priority set")
}

// ===========================================================================
// Notrack
// ===========================================================================

func TestNftRef_notrack(t *testing.T) {
	testBoth(t, cfgIPRawPre,
		"udp dport 53 notrack",
		`provider::nftables::match_udp_dport(53), provider::nftables::notrack()`,
		"notrack")
}

// ===========================================================================
// Queue
// ===========================================================================

func TestNftRef_queue(t *testing.T) {
	testBoth(t, cfgIPInput,
		"tcp dport 8080 queue num 1",
		`provider::nftables::match_tcp_dport(8080), provider::nftables::queue(1)`,
		"queue")
}

// ===========================================================================
// Redirect
// ===========================================================================

func TestNftRef_redirect(t *testing.T) {
	testBoth(t, cfgIPNatPre,
		"tcp dport 80 redirect to :3128",
		`provider::nftables::match_tcp_dport(80), provider::nftables::redirect(3128)`,
		"redirect")
}

// ===========================================================================
// Combined / real-world expressions
// ===========================================================================

func TestNftRef_sshFromSubnet(t *testing.T) {
	testBoth(t, cfgIPInput,
		"ip saddr 10.0.0.0/8 tcp dport 22 ct state new counter accept",
		`provider::nftables::match_ip_saddr("10.0.0.0/8"), provider::nftables::match_tcp_dport(22), provider::nftables::match_ct_state(["new"]), provider::nftables::counter(), provider::nftables::accept()`,
		"10.0.0.0/8", "dport 22")
}

func TestNftRef_rateLimitedPing(t *testing.T) {
	testBoth(t, cfgIPInput,
		"icmp type echo-request limit rate 10/second burst 20 packets accept",
		`provider::nftables::match_icmp_type("echo-request"), provider::nftables::limit_burst(10, "second", 20), provider::nftables::accept()`,
		"10/second", "burst")
}

func TestNftRef_dnatPortForward(t *testing.T) {
	testBoth(t, cfgIPNatPre,
		"iifname lo tcp dport 8080 dnat to 10.0.0.5:80",
		`provider::nftables::match_iifname("lo"), provider::nftables::match_tcp_dport(8080), provider::nftables::dnat_port("10.0.0.5", 80)`,
		`iifname "lo"`, "10.0.0.5")
}

func TestNftRef_masqueradeOutbound(t *testing.T) {
	testBoth(t, cfgIPNatPost,
		"oifname lo masquerade",
		`provider::nftables::match_oifname("lo"), provider::nftables::masquerade()`,
		`oifname "lo"`, "masquerade")
}
