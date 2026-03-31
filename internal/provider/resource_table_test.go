package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/terraform-providers/terraform-provider-nftables/internal/testutils"
)

func TestAccTableResource_basic(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "test_filter"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_table.test", "family", "ip"),
					resource.TestCheckResourceAttr("nftables_table.test", "name", "test_filter"),
					resource.TestCheckResourceAttr("nftables_table.test", "dormant", "false"),
					testutils.CheckNft(t, ns, []string{"list", "tables"}, "table ip test_filter"),
				),
			},
		},
	})

	// Verify cleanup
	testutils.AssertNftNotContains(t, ns, []string{"list", "tables"}, "test_filter")
}

func TestAccTableResource_ip6(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test6" {
  family = "ip6"
  name   = "test6_filter"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_table.test6", "family", "ip6"),
					resource.TestCheckResourceAttr("nftables_table.test6", "name", "test6_filter"),
				),
			},
		},
	})
}

func TestAccTableResource_inet(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "inet" {
  family = "inet"
  name   = "test_inet"
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.inet", "family", "inet"),
			},
		},
	})
}

func TestAccTableResource_bridge(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "bridge" {
  family = "bridge"
  name   = "test_bridge"
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.bridge", "family", "bridge"),
			},
		},
	})
}

func TestAccTableResource_arp(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "arp" {
  family = "arp"
  name   = "test_arp"
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.arp", "family", "arp"),
			},
		},
	})
}

func TestAccTableResource_netdev(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "netdev" {
  family = "netdev"
  name   = "test_netdev"
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.netdev", "family", "netdev"),
			},
		},
	})
}

func TestAccTableResource_dormant(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "dormant" {
  family  = "ip"
  name    = "test_dormant"
  dormant = true
}`,
				Check: resource.TestCheckResourceAttr("nftables_table.dormant", "dormant", "true"),
			},
		},
	})
}

func TestAccTableResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "import_test" {
  family = "ip"
  name   = "import_table"
}`,
			},
			{
				ResourceName:  "nftables_table.import_test",
				ImportState:   true,
				ImportStateId: "ip|import_table",
				ImportStateVerify: true,
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerifyIgnore: []string{"dormant"},
			},
		},
	})
}
