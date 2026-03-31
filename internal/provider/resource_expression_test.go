package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// --- ICMPv6 tests ---

func TestAccRuleResource_icmpv6Type(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "icmpv6" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 type echo-request accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.icmpv6", "handle"),
			},
		},
	})
}

func TestAccRuleResource_icmpv6NdNeighborSolicit(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "nd" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "icmpv6 type nd-neighbor-solicit accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.nd", "handle"),
			},
		},
	})
}

// --- IP header field tests ---

func TestAccRuleResource_ipVersion(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip version 4 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipHdrlength(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip hdrlength 5 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipId(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip id 1234 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipFragOff(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip frag-off 0 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipChecksum(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip checksum 0x1234 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- IPv6 header field tests ---

func TestAccRuleResource_ip6Nexthdr(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "nexthdr" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "ip6 nexthdr tcp accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.nexthdr", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ip6FlowLabel(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "flowlabel" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "ip6 flowlabel 0x12345 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.flowlabel", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ip6DaddrCIDR(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "ip6cidr" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "ip6 daddr fd00::/8 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.ip6cidr", "handle"),
			},
		},
	})
}

// --- TCP header field tests ---

func TestAccRuleResource_tcpSequence(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp sequence 0 drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_tcpWindow(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp window 0 drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_tcpFlagsSynAck(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp flags syn|ack accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- UDP tests ---

func TestAccRuleResource_udpLength(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "udp length 100 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- ICMP field tests ---

func TestAccRuleResource_icmpCode(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp code 0 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_icmpId(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp id 1234 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_icmpSequence(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp sequence 1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Meta match tests ---

func TestAccRuleResource_metaOifname(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "oifname lo accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaSkuid(t *testing.T) {
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
resource "nftables_chain" "output" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "output"
  type     = "filter"
  hook     = "output"
  priority = 0
  policy   = "accept"
}
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.output.name
  expression = "meta skuid 1000 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaPkttype(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "meta pkttype broadcast drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaNfproto(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: inetBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "meta nfproto ipv4 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaPrioritySet(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "meta priority set 0x10"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- CT match tests ---

func TestAccRuleResource_ctMark(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct mark 0x1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ctStateUntracked(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct state untracked accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Negation tests ---

func TestAccRuleResource_ipSaddrNeq(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip saddr != 10.0.0.1 drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_tcpDportNeq(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport != 22 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Limit variations ---

func TestAccRuleResource_limitOverRate(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "limit rate over 100/minute drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_limitPerHour(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "limit rate 1000/hour accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Log variations ---

func TestAccRuleResource_logGroup(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "log group 1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- NAT variations ---

func TestAccRuleResource_masqueradeRandom(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.postrouting.name
  expression = "masquerade random"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_snatWithPort(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.postrouting.name
  expression = "snat to 192.168.1.1:1024-65535"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- DCCP type test ---

func TestAccRuleResource_dccpType(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "dccp type request accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Reject variations ---

func TestAccRuleResource_rejectICMPv6(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: inetBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "reject with icmpx type admin-prohibited"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Complex combined expressions ---

func TestAccRuleResource_fullFirewallRule(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip saddr 192.168.1.0/24 tcp dport 443 ct state new counter log prefix \"HTTPS:\" accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_iifnameAndDrop(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "iifname lo ip saddr 127.0.0.1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Mark mangling ---

func TestAccRuleResource_markSetFromRule(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 80 mark set 0x1"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- SCTP vtag ---

func TestAccRuleResource_sctpVtag(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "sctp vtag 12345 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- AH header test ---

func TestAccRuleResource_ahHdrlength(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ah hdrlength 4 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}
