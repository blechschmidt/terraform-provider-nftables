package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func TestAccCIDR_loadSaddrCmpIPv4(t *testing.T) {
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_saddr(),
    provider::nftables::cmp_ipv4("10.0.0.0/8"),
    provider::nftables::drop(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "10.0.0.0/8"),
			),
		}},
	})
}

func TestAccCIDR_loadDaddrCmpIPv4_16(t *testing.T) {
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_daddr(),
    provider::nftables::cmp_ipv4("192.168.0.0/16"),
    provider::nftables::accept(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "192.168.0.0/16"),
			),
		}},
	})
}

func TestAccCIDR_loadDaddrCmpIPv4_24(t *testing.T) {
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_saddr(),
    provider::nftables::cmp_ipv4("172.16.0.0/24"),
    provider::nftables::accept(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
		}},
	})
}

func TestAccCIDR_loadSaddrCmpIPv4_exact(t *testing.T) {
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip_saddr(),
    provider::nftables::cmp_ipv4("192.168.1.1"),
    provider::nftables::accept(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "192.168.1.1"),
			),
		}},
	})
}

func TestAccCIDR_loadIP6SaddrCmpIPv6(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testutils.ProviderConfig(ns) + `
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_ip6_saddr(),
    provider::nftables::cmp_ipv6("fd00::/8"),
    provider::nftables::accept(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "fd00::/8"),
			),
		}},
	})
}

func TestAccCIDR_loadTCPDportCmpPort(t *testing.T) {
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
resource "nftables_rule" "r" {
  family = nftables_table.t.family
  table  = nftables_table.t.name
  chain  = nftables_chain.c.name
  expr = provider::nftables::combine(
    provider::nftables::load_tcp_dport(),
    provider::nftables::cmp_port(443),
    provider::nftables::accept(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.r", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "ruleset"}, "443"),
			),
		}},
	})
}
