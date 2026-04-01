package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// Tests for provider-defined functions (provider::nftables::*)

func TestAccProvFunc_combineAccept(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::accept(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_combineTCPDportAccept(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
				testutils.CheckNft(t, ns, []string{"list", "chain", "ip", "filter", "input"}, "dport 22"),
			),
		}},
	})
}

func TestAccProvFunc_combineIPSaddrDrop(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.0.0/8"),
    provider::nftables::drop(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_combineCTStateEstablished(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_ct_state(["established", "related"]),
    provider::nftables::accept(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_combineIifnameAccept(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::accept(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_combineLogLimit(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::limit(5, "minute"),
    provider::nftables::log("DROP", "warn"),
    provider::nftables::drop(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_masquerade(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: natBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.nat.family
  table  = nftables_table.nat.name
  chain  = nftables_chain.postrouting.name
  expr   = provider::nftables::combine(
    provider::nftables::match_oifname("lo"),
    provider::nftables::masquerade(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_dnatPort(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: natBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.nat.family
  table  = nftables_table.nat.name
  chain  = nftables_chain.prerouting.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(8080),
    provider::nftables::dnat_port("10.0.0.5", 80),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_setMark(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::set_mark(100),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_icmpType(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit_burst(10, "second", 20),
    provider::nftables::accept(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}

func TestAccProvFunc_rejectTCPReset(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::reject_tcp_reset(),
  )
}`,
			Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
		}},
	})
}
