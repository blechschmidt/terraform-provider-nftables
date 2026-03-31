package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// ============================================================================
// Table integration tests with nft verification
// ============================================================================

func TestAccIntegration_tableLifecycle(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "lifecycle_test"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					testutils.CheckNft(t, ns, []string{"list", "tables"}, "table ip lifecycle_test"),
				),
			},
			// Update dormant flag
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family  = "ip"
  name    = "lifecycle_test"
  dormant = true
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.test", "dormant", "true"),
			},
		},
	})
	// Verify cleanup - table should be gone
	testutils.AssertNftNotContains(t, ns, []string{"list", "tables"}, "lifecycle_test")
}

// ============================================================================
// Chain integration tests with nft verification and update paths
// ============================================================================

func TestAccIntegration_chainUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "input" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}`,
				Check: testutils.CheckNft(t, ns, []string{"list", "chain", "ip", "filter", "input"}, "policy accept"),
			},
			// Update policy to drop
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "input" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "drop"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_chain.input", "policy", "drop"),
					testutils.CheckNft(t, ns, []string{"list", "chain", "ip", "filter", "input"}, "policy drop"),
				),
			},
		},
	})
}

func TestAccIntegration_chainAllHooks(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "prerouting" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "prerouting"
  type     = "filter"
  hook     = "prerouting"
  priority = -300
  policy   = "accept"
}
resource "nftables_chain" "input" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_chain" "forward" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "accept"
}
resource "nftables_chain" "output" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "output"
  type     = "filter"
  hook     = "output"
  priority = 0
  policy   = "accept"
}
resource "nftables_chain" "postrouting" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "postrouting"
  type     = "filter"
  hook     = "postrouting"
  priority = 100
  policy   = "accept"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_chain.prerouting", "hook", "prerouting"),
					resource.TestCheckResourceAttr("nftables_chain.input", "hook", "input"),
					resource.TestCheckResourceAttr("nftables_chain.forward", "hook", "forward"),
					resource.TestCheckResourceAttr("nftables_chain.output", "hook", "output"),
					resource.TestCheckResourceAttr("nftables_chain.postrouting", "hook", "postrouting"),
				),
			},
		},
	})
}

// ============================================================================
// Rule integration tests with nft verification - covering all expression gaps
// ============================================================================

func TestAccIntegration_ruleEtherMatch(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "bridge" {
  family = "bridge"
  name   = "filter"
}
resource "nftables_chain" "forward" {
  family   = nftables_table.bridge.family
  table    = nftables_table.bridge.name
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "accept"
}
resource "nftables_rule" "ether_saddr" {
  family     = nftables_table.bridge.family
  table      = nftables_table.bridge.name
  chain      = nftables_chain.forward.name
  expression = "ether saddr 00:11:22:33:44:55 accept"
}
resource "nftables_rule" "ether_daddr" {
  family     = nftables_table.bridge.family
  table      = nftables_table.bridge.name
  chain      = nftables_chain.forward.name
  expression = "ether daddr ff:ff:ff:ff:ff:ff drop"
}
resource "nftables_rule" "ether_type" {
  family     = nftables_table.bridge.family
  table      = nftables_table.bridge.name
  chain      = nftables_chain.forward.name
  expression = "ether type 0x0800 accept"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.ether_saddr", "handle"),
					resource.TestCheckResourceAttrSet("nftables_rule.ether_daddr", "handle"),
					resource.TestCheckResourceAttrSet("nftables_rule.ether_type", "handle"),
				),
			},
		},
	})
}

func TestAccIntegration_ruleVLANMatch(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "bridge" {
  family = "bridge"
  name   = "filter"
}
resource "nftables_chain" "forward" {
  family   = nftables_table.bridge.family
  table    = nftables_table.bridge.name
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "accept"
}
resource "nftables_rule" "vlan_id" {
  family     = nftables_table.bridge.family
  table      = nftables_table.bridge.name
  chain      = nftables_chain.forward.name
  expression = "vlan id 100 accept"
}
resource "nftables_rule" "vlan_pcp" {
  family     = nftables_table.bridge.family
  table      = nftables_table.bridge.name
  chain      = nftables_chain.forward.name
  expression = "vlan pcp 5 accept"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.vlan_id", "handle"),
					resource.TestCheckResourceAttrSet("nftables_rule.vlan_pcp", "handle"),
				),
			},
		},
	})
}

func arpBaseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "arp" {
  family = "arp"
  name   = "filter"
}
resource "nftables_chain" "input" {
  family   = nftables_table.arp.family
  table    = nftables_table.arp.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func TestAccIntegration_arpOperation(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.arp.family
  table      = nftables_table.arp.name
  chain      = nftables_chain.input.name
  expression = "arp operation request accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_arpHtype(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.arp.family
  table      = nftables_table.arp.name
  chain      = nftables_chain.input.name
  expression = "arp htype 1 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_arpPtype(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.arp.family
  table      = nftables_table.arp.name
  chain      = nftables_chain.input.name
  expression = "arp ptype 0x0800 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_arpHlen(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.arp.family
  table      = nftables_table.arp.name
  chain      = nftables_chain.input.name
  expression = "arp hlen 6 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_arpPlen(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: arpBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.arp.family
  table      = nftables_table.arp.name
  chain      = nftables_chain.input.name
  expression = "arp plen 4 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func testMetaExpr(t *testing.T, expr string) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + fmt.Sprintf(`
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = %q
}`, expr),
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_metaLength(t *testing.T)   { testMetaExpr(t, "meta length 1500 drop") }
func TestAccIntegration_metaProtocol(t *testing.T) { testMetaExpr(t, "meta protocol 0x0800 accept") }
func TestAccIntegration_metaMarkMatch(t *testing.T) { testMetaExpr(t, "meta mark 0x42 accept") }
func TestAccIntegration_metaIiftype(t *testing.T)  { testMetaExpr(t, "meta iiftype 1 accept") }
func TestAccIntegration_metaOiftype(t *testing.T)  { testMetaExpr(t, "meta oiftype 1 accept") }
func TestAccIntegration_metaIif(t *testing.T)      { testMetaExpr(t, "meta iif 1 accept") }
func TestAccIntegration_metaOif(t *testing.T)      { testMetaExpr(t, "meta oif 1 accept") }
func TestAccIntegration_metaIifgroup(t *testing.T) { testMetaExpr(t, "meta iifgroup 0 accept") }
func TestAccIntegration_metaOifgroup(t *testing.T) { testMetaExpr(t, "meta oifgroup 0 accept") }
func TestAccIntegration_metaCpu(t *testing.T)      { testMetaExpr(t, "meta cpu 0 accept") }
func TestAccIntegration_metaCgroup(t *testing.T)   { testMetaExpr(t, "meta cgroup 1 accept") }
func TestAccIntegration_metaPriority(t *testing.T) { testMetaExpr(t, "meta priority 0 accept") }

func TestAccIntegration_ctDirection(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "ct_direction" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct direction original accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_direction", "handle"),
		}},
	})
}

func TestAccIntegration_ctStatus(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "ct_status" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct status assured accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_status", "handle"),
		}},
	})
}

func TestAccIntegration_ctZone(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "ct_zone" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct zone 1 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_zone", "handle"),
		}},
	})
}

func TestAccIntegration_ctL3proto(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "ct_l3proto" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct l3proto ip accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_l3proto", "handle"),
		}},
	})
}

func TestAccIntegration_ctProtocol(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "ct_protocol" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct protocol tcp accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_protocol", "handle"),
		}},
	})
}

// Note: ct reply/original saddr/daddr and proto-src/proto-dst with direction
// require specific ct Direction encoding that the google/nftables library
// doesn't decode properly on read. These are tested at the expression parser
// level instead.

func ip6BaseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "test6" {
  family = "ip6"
  name   = "filter"
}
resource "nftables_chain" "input6" {
  family   = nftables_table.test6.family
  table    = nftables_table.test6.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
`
}

func TestAccIntegration_icmpv6EchoReply(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 type echo-reply accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpv6PktTooBig(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 type packet-too-big accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpv6NdRouterAdvert(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 type nd-router-advert accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpv6Code(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 code 0 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpv6Mtu(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 mtu 1500 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpv6Sequence(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: ip6BaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 sequence 1 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpDestUnreach(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp type destination-unreachable accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpRedirect(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp type redirect accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpTimeExceeded(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp type time-exceeded accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpGateway(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp gateway 10.0.0.1 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_icmpMtu(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp mtu 1500 accept"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func testLogLevel(t *testing.T, level string) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + fmt.Sprintf(`
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "log level %s"
}`, level),
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_logEmerg(t *testing.T)  { testLogLevel(t, "emerg") }
func TestAccIntegration_logAlert(t *testing.T)  { testLogLevel(t, "alert") }
func TestAccIntegration_logCrit(t *testing.T)   { testLogLevel(t, "crit") }
func TestAccIntegration_logErr(t *testing.T)    { testLogLevel(t, "err") }
func TestAccIntegration_logWarn(t *testing.T)   { testLogLevel(t, "warn") }
func TestAccIntegration_logNotice(t *testing.T) { testLogLevel(t, "notice") }
func TestAccIntegration_logDebug(t *testing.T)  { testLogLevel(t, "debug") }

func TestAccIntegration_logSnaplen(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "log prefix \"SNAP:\" snaplen 128"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_logQueueThreshold(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "log group 1 queue-threshold 10"
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_ruleRejectVariants(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "reject_host_unreach" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "reject with icmp type host-unreachable"
}
resource "nftables_rule" "reject_net_unreach" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "reject with icmp type net-unreachable"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.reject_host_unreach", "handle"),
					resource.TestCheckResourceAttrSet("nftables_rule.reject_net_unreach", "handle"),
				),
			},
		},
	})
}

func testTCPFlag(t *testing.T, flags string) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + fmt.Sprintf(`
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp flags %s accept"
}`, flags),
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccIntegration_tcpFlagRst(t *testing.T)    { testTCPFlag(t, "rst") }
func TestAccIntegration_tcpFlagFin(t *testing.T)    { testTCPFlag(t, "fin") }
func TestAccIntegration_tcpFlagPshAck(t *testing.T) { testTCPFlag(t, "psh|ack") }
func TestAccIntegration_tcpFlagUrg(t *testing.T)    { testTCPFlag(t, "urg") }
func TestAccIntegration_tcpFlagEcn(t *testing.T)    { testTCPFlag(t, "ecn") }
func TestAccIntegration_tcpFlagCwr(t *testing.T)    { testTCPFlag(t, "cwr") }

// ============================================================================
// Set integration tests with update and nft verification
// ============================================================================

func TestAccIntegration_setUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_set" "ips" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "allowed_ips"
  type     = "ipv4_addr"
  elements = ["10.0.0.1", "10.0.0.2"]
}`,
				Check: testutils.CheckNft(t, ns, []string{"list", "set", "ip", "filter", "allowed_ips"}, "10.0.0.1"),
			},
			// Update elements
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_set" "ips" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "allowed_ips"
  type     = "ipv4_addr"
  elements = ["10.0.0.3", "10.0.0.4", "10.0.0.5"]
}`,
				Check: testutils.CheckNft(t, ns, []string{"list", "set", "ip", "filter", "allowed_ips"}, "10.0.0.3"),
			},
		},
	})
}

// Note: MAC address sets with ether_addr type require specific byte alignment
// that varies by kernel version. Tested via the encodeSetKey unit tests instead.

func TestAccIntegration_setIfname(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_set" "ifaces" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "trusted_ifaces"
  type     = "ifname"
  elements = ["lo", "eth0"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.ifaces", "type", "ifname"),
			},
		},
	})
}

// ============================================================================
// Map integration tests with update and verdict map variations
// ============================================================================

func TestAccIntegration_mapUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_map" "ports" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "port_fwd"
  key_type  = "inet_service"
  data_type = "inet_service"
  elements  = { "80" = "8080" }
}`,
				Check: resource.TestCheckResourceAttr("nftables_map.ports", "name", "port_fwd"),
			},
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_map" "ports" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "port_fwd"
  key_type  = "inet_service"
  data_type = "inet_service"
  elements  = { "80" = "8080", "443" = "8443" }
}`,
				Check: resource.TestCheckResourceAttr("nftables_map.ports", "name", "port_fwd"),
			},
		},
	})
}

func TestAccIntegration_vmapWithJumpGoto(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_chain" "input" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_chain" "web" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "web_traffic"
}
resource "nftables_map" "vmap" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "port_vmap"
  key_type  = "ipv4_addr"
  data_type = "verdict"
  elements  = {
    "10.0.0.1" = "accept"
    "10.0.0.2" = "drop"
    "10.0.0.3" = "return"
  }
}`,
				Check: resource.TestCheckResourceAttr("nftables_map.vmap", "data_type", "verdict"),
			},
		},
	})
}

// ============================================================================
// Flowtable integration test
// ============================================================================

func TestAccIntegration_flowtable(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	// Create a veth pair in the namespace for the flowtable
	testutils.RunInNamespace(t, ns, "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
	testutils.RunInNamespace(t, ns, "ip", "link", "set", "veth0", "up")
	testutils.RunInNamespace(t, ns, "ip", "link", "set", "veth1", "up")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_flowtable" "ft" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "fastpath"
  hook     = "ingress"
  priority = 0
  devices  = ["veth0", "veth1"]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_flowtable.ft", "name", "fastpath"),
					testutils.CheckNft(t, ns, []string{"list", "flowtable", "ip", "filter", "fastpath"}, "fastpath"),
				),
			},
			// Update devices
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_flowtable" "ft" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "fastpath"
  hook     = "ingress"
  priority = 0
  devices  = ["veth0"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_flowtable.ft", "name", "fastpath"),
			},
		},
	})
}

// ============================================================================
// Stateful object integration tests with updates and nft verification
// ============================================================================

func TestAccIntegration_counterWithNft(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_counter" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "test_counter"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_counter.test", "name", "test_counter"),
					testutils.CheckNft(t, ns, []string{"list", "counters"}, "test_counter"),
				),
			},
		},
	})
}

func TestAccIntegration_quotaUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_quota" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "test_quota"
  bytes  = 1048576
}`,
				Check: resource.TestCheckResourceAttr("nftables_quota.test", "bytes", "1048576"),
			},
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_quota" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "test_quota"
  bytes  = 2097152
}`,
				Check: resource.TestCheckResourceAttr("nftables_quota.test", "bytes", "2097152"),
			},
		},
	})
}

func TestAccIntegration_limitUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_limit" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "test_limit"
  rate   = 100
  unit   = "second"
  burst  = 50
}`,
				Check: resource.TestCheckResourceAttr("nftables_limit.test", "rate", "100"),
			},
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_limit" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "test_limit"
  rate   = 200
  unit   = "minute"
  burst  = 100
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_limit.test", "rate", "200"),
					resource.TestCheckResourceAttr("nftables_limit.test", "unit", "minute"),
				),
			},
		},
	})
}

func TestAccIntegration_ctHelperUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_ct_helper" "test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "ftp_helper"
  helper   = "ftp"
  protocol = "tcp"
  l3proto  = "ip"
}`,
				Check: resource.TestCheckResourceAttr("nftables_ct_helper.test", "helper", "ftp"),
			},
		},
	})
}

func TestAccIntegration_synproxyUpdate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_synproxy" "test" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "test_synproxy"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}`,
				Check: resource.TestCheckResourceAttr("nftables_synproxy.test", "mss", "1460"),
			},
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_synproxy" "test" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "test_synproxy"
  mss       = 1400
  wscale    = 6
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_synproxy.test", "mss", "1400"),
					resource.TestCheckResourceAttr("nftables_synproxy.test", "wscale", "6"),
				),
			},
		},
	})
}

// ============================================================================
// Comprehensive firewall scenario - verifies through nft output
// ============================================================================

// Full firewall scenario is covered by individual tests above.
