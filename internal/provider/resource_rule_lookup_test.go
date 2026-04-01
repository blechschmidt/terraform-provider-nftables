package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func TestAccLookup_ipSaddrSet(t *testing.T) {
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
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_set" "blocked" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "blocked_ips"
  type     = "ipv4_addr"
  elements = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_saddr(),
    provider::nftables::lookup("blocked_ips"),
    provider::nftables::drop(),
  )
  depends_on = [nftables_set.blocked]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "@blocked_ips"),
			),
		}},
	})
}

func TestAccLookup_tcpDportSet(t *testing.T) {
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
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_set" "ports" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "allowed_ports"
  type     = "inet_service"
  elements = ["22", "80", "443"]
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_tcp_dport(),
    provider::nftables::lookup("allowed_ports"),
    provider::nftables::accept(),
  )
  depends_on = [nftables_set.ports]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "@allowed_ports"),
			),
		}},
	})
}

func TestAccLookup_invertedSet(t *testing.T) {
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
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_set" "trusted" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "trusted_ips"
  type     = "ipv4_addr"
  elements = ["10.0.0.1"]
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_saddr(),
    provider::nftables::lookup_inv("trusted_ips"),
    provider::nftables::drop(),
  )
  depends_on = [nftables_set.trusted]
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func TestAccLookup_udpDportSet(t *testing.T) {
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
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_set" "dns_ports" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "dns_ports"
  type     = "inet_service"
  elements = ["53", "5353"]
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_udp_dport(),
    provider::nftables::lookup("dns_ports"),
    provider::nftables::accept(),
  )
  depends_on = [nftables_set.dns_ports]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "@dns_ports"),
			),
		}},
	})
}

func TestAccLookup_iifnameSet(t *testing.T) {
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
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}
resource "nftables_set" "ifaces" {
  family   = nftables_table.t.family
  table    = nftables_table.t.name
  name     = "trusted_ifaces"
  type     = "ifname"
  elements = ["lo"]
}
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_meta_iifname(),
    provider::nftables::lookup("trusted_ifaces"),
    provider::nftables::accept(),
  )
  depends_on = [nftables_set.ifaces]
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "@trusted_ifaces"),
			),
		}},
	})
}
