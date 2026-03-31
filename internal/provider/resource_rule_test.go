package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func baseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
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
`
}

func inetBaseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "inet"
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
`
}

func natBaseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "nat" {
  family = "ip"
  name   = "nat"
}

resource "nftables_chain" "postrouting" {
  family   = nftables_table.nat.family
  table    = nftables_table.nat.name
  name     = "postrouting"
  type     = "nat"
  hook     = "postrouting"
  priority = 100
  policy   = "accept"
}

resource "nftables_chain" "prerouting" {
  family   = nftables_table.nat.family
  table    = nftables_table.nat.name
  name     = "prerouting"
  type     = "nat"
  hook     = "prerouting"
  priority = -100
  policy   = "accept"
}
`
}

// --- IP match tests ---

func TestAccRuleResource_ipSaddr(t *testing.T) {
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
  expression = "ip saddr 10.0.0.1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipSaddrCIDR(t *testing.T) {
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
  expression = "ip saddr 192.168.0.0/24 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipDaddr(t *testing.T) {
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
  expression = "ip daddr 10.0.0.0/8 drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipProtocol(t *testing.T) {
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
  expression = "ip protocol tcp accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipTTL(t *testing.T) {
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
  expression = "ip ttl 64 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipDSCP(t *testing.T) {
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
  expression = "ip dscp 0x2e accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ipLength(t *testing.T) {
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
  expression = "ip length 1500 drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- TCP match tests ---

func TestAccRuleResource_tcpDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "ssh" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 22 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.ssh", "handle"),
			},
		},
	})
}

func TestAccRuleResource_tcpSport(t *testing.T) {
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
  expression = "tcp sport 80 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_tcpFlags(t *testing.T) {
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
  expression = "tcp flags syn drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- UDP match tests ---

func TestAccRuleResource_udpDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "dns" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "udp dport 53 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.dns", "handle"),
			},
		},
	})
}

// --- ICMP match tests ---

func TestAccRuleResource_icmpType(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "icmp" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp type echo-request accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.icmp", "handle"),
			},
		},
	})
}

func TestAccRuleResource_icmpEchoReply(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "icmp" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "icmp type echo-reply accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.icmp", "handle"),
			},
		},
	})
}

// --- CT match tests ---

func TestAccRuleResource_ctState(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "established" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct state established,related accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.established", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ctStateNew(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "new" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct state new accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.new", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ctStateInvalid(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "invalid" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct state invalid drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.invalid", "handle"),
			},
		},
	})
}

// --- Meta match tests ---

func TestAccRuleResource_metaIifname(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "lo" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "iifname lo accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.lo", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaL4proto(t *testing.T) {
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
  expression = "meta l4proto tcp accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaMarkSet(t *testing.T) {
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
  expression = "meta mark set 0x1"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleResource_metaNftrace(t *testing.T) {
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
  expression = "meta nftrace set 1"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// --- Counter, Limit, Log ---

func TestAccRuleResource_counter(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "counted" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 80 counter accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.counted", "handle"),
			},
		},
	})
}

func TestAccRuleResource_limit(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "limited" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "limit rate 10/second burst 5 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.limited", "handle"),
			},
		},
	})
}

func TestAccRuleResource_log(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "logged" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 22 log prefix \"SSH:\" level info accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.logged", "handle"),
			},
		},
	})
}

// --- Reject ---

func TestAccRuleResource_reject(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "rejected" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "reject"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.rejected", "handle"),
			},
		},
	})
}

func TestAccRuleResource_rejectTCPReset(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "tcp_rst" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 80 reject with tcp reset"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.tcp_rst", "handle"),
			},
		},
	})
}

func TestAccRuleResource_rejectICMP(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "icmp_reject" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "reject with icmp type admin-prohibited"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.icmp_reject", "handle"),
			},
		},
	})
}

// --- NAT ---

func TestAccRuleResource_masquerade(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "masq" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.postrouting.name
  expression = "masquerade"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.masq", "handle"),
			},
		},
	})
}

func TestAccRuleResource_snat(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "snat" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.postrouting.name
  expression = "snat to 192.168.1.1"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.snat", "handle"),
			},
		},
	})
}

func TestAccRuleResource_dnat(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "dnat" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.prerouting.name
  expression = "tcp dport 80 dnat to 10.0.0.1:8080"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.dnat", "handle"),
			},
		},
	})
}

func TestAccRuleResource_redirect(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "redir" {
  family     = nftables_table.nat.family
  table      = nftables_table.nat.name
  chain      = nftables_chain.prerouting.name
  expression = "tcp dport 80 redirect to :8080"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.redir", "handle"),
			},
		},
	})
}

// --- Notrack ---

func TestAccRuleResource_notrack(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "raw" {
  family = "ip"
  name   = "raw"
}

resource "nftables_chain" "prerouting" {
  family   = nftables_table.raw.family
  table    = nftables_table.raw.name
  name     = "prerouting"
  type     = "filter"
  hook     = "prerouting"
  priority = -300
  policy   = "accept"
}

resource "nftables_rule" "notrack" {
  family     = nftables_table.raw.family
  table      = nftables_table.raw.name
  chain      = nftables_chain.prerouting.name
  expression = "tcp dport 80 notrack"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.notrack", "handle"),
			},
		},
	})
}

// --- Jump/Goto ---

func TestAccRuleResource_jump(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_chain" "custom" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "custom_chain"
}

resource "nftables_rule" "jump" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 80 jump custom_chain"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.jump", "handle"),
			},
		},
	})
}

func TestAccRuleResource_goto(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_chain" "custom" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "custom_chain"
}

resource "nftables_rule" "goto_rule" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 443 goto custom_chain"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.goto_rule", "handle"),
			},
		},
	})
}

// --- Queue ---

func TestAccRuleResource_queue(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "queued" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "queue num 1 bypass"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.queued", "handle"),
			},
		},
	})
}

// --- Verdict: accept, drop, return, continue ---

func TestAccRuleResource_drop(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "drop_all" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "drop"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.drop_all", "handle"),
			},
		},
	})
}

func TestAccRuleResource_accept(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "accept_all" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.accept_all", "handle"),
			},
		},
	})
}

// --- CT mark set ---

func TestAccRuleResource_ctMarkSet(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "ct_mark" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct mark set 0x42"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.ct_mark", "handle"),
			},
		},
	})
}

// --- IP6 match tests ---

func TestAccRuleResource_ip6Saddr(t *testing.T) {
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

resource "nftables_rule" "ip6_saddr" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "ip6 saddr ::1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.ip6_saddr", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ip6Hoplimit(t *testing.T) {
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

resource "nftables_rule" "hoplimit" {
  family     = nftables_table.test6.family
  table      = nftables_table.test6.name
  chain      = nftables_chain.input6.name
  expression = "ip6 hoplimit 255 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.hoplimit", "handle"),
			},
		},
	})
}

// --- SCTP / DCCP / ESP / AH / COMP / UDPLite ---

func TestAccRuleResource_sctpDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "sctp" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "sctp dport 5060 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.sctp", "handle"),
			},
		},
	})
}

func TestAccRuleResource_espSpi(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "esp" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "esp spi 0x100 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.esp", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ahSpi(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "ah" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ah spi 0x200 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.ah", "handle"),
			},
		},
	})
}

func TestAccRuleResource_compCpi(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "comp" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "comp cpi 1 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.comp", "handle"),
			},
		},
	})
}

func TestAccRuleResource_udpliteDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "udplite" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "udplite dport 5060 accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.udplite", "handle"),
			},
		},
	})
}

// --- Combined expressions ---

func TestAccRuleResource_combinedIPTCPCounter(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "combo" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ip saddr 10.0.0.0/8 tcp dport 22 counter accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.combo", "handle"),
			},
		},
	})
}

func TestAccRuleResource_ctStateAndTCPDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "combo2" {
  family     = nftables_table.test.family
  table      = nftables_table.test.name
  chain      = nftables_chain.input.name
  expression = "ct state new tcp dport 80 counter log prefix \"HTTP:\" accept"
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.combo2", "handle"),
			},
		},
	})
}
