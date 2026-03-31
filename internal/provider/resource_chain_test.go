package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func TestAccChainResource_baseChain(t *testing.T) {
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
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_chain.input", "name", "input"),
					resource.TestCheckResourceAttr("nftables_chain.input", "type", "filter"),
					resource.TestCheckResourceAttr("nftables_chain.input", "hook", "input"),
					resource.TestCheckResourceAttr("nftables_chain.input", "priority", "0"),
					resource.TestCheckResourceAttr("nftables_chain.input", "policy", "accept"),
					testutils.CheckNft(t, ns, []string{"list", "chain", "ip", "filter", "input"}, "type filter hook input"),
				),
			},
		},
	})
}

func TestAccChainResource_dropPolicy(t *testing.T) {
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

resource "nftables_chain" "forward" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "drop"
}`,
				Check: resource.TestCheckResourceAttr("nftables_chain.forward", "policy", "drop"),
			},
		},
	})
}

func TestAccChainResource_regularChain(t *testing.T) {
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

resource "nftables_chain" "custom" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "custom_chain"
}`,
				Check: resource.TestCheckResourceAttr("nftables_chain.custom", "name", "custom_chain"),
			},
		},
	})
}

func TestAccChainResource_natChain(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "nat"
}

resource "nftables_chain" "postrouting" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "postrouting"
  type     = "nat"
  hook     = "postrouting"
  priority = 100
  policy   = "accept"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_chain.postrouting", "type", "nat"),
					resource.TestCheckResourceAttr("nftables_chain.postrouting", "hook", "postrouting"),
					resource.TestCheckResourceAttr("nftables_chain.postrouting", "priority", "100"),
				),
			},
		},
	})
}

func TestAccChainResource_routeChain(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "mangle"
}

resource "nftables_chain" "output" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "output"
  type     = "route"
  hook     = "output"
  priority = -150
  policy   = "accept"
}`,
				Check: resource.TestCheckResourceAttr("nftables_chain.output", "type", "route"),
			},
		},
	})
}

func TestAccChainResource_inetFamily(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "inet" {
  family = "inet"
  name   = "filter"
}

resource "nftables_chain" "input" {
  family   = nftables_table.inet.family
  table    = nftables_table.inet.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}`,
				Check: resource.TestCheckResourceAttr("nftables_chain.input", "family", "inet"),
			},
		},
	})
}

func TestAccChainResource_import(t *testing.T) {
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

resource "nftables_chain" "import_test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "import_chain"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "accept"
}`,
			},
			{
				ResourceName:  "nftables_chain.import_test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_chain",
				ImportStateVerify: true,
				ImportStateVerifyIdentifierAttribute: "name",
			},
		},
	})
}
