package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func TestAccMapResource_basic(t *testing.T) {
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

resource "nftables_map" "port_redirect" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "port_redirect"
  key_type  = "inet_service"
  data_type = "inet_service"
  elements  = {
    "80"  = "8080"
    "443" = "8443"
  }
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_map.port_redirect", "name", "port_redirect"),
					resource.TestCheckResourceAttr("nftables_map.port_redirect", "key_type", "inet_service"),
					resource.TestCheckResourceAttr("nftables_map.port_redirect", "data_type", "inet_service"),
				),
			},
		},
	})
}

func TestAccMapResource_verdictMap(t *testing.T) {
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

resource "nftables_map" "vmap" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "vmap_test"
  key_type  = "ipv4_addr"
  data_type = "verdict"
  elements  = {
    "10.0.0.1" = "accept"
    "10.0.0.2" = "drop"
  }
}`,
				Check: resource.TestCheckResourceAttr("nftables_map.vmap", "data_type", "verdict"),
			},
		},
	})
}

func TestAccMapResource_ipToIp(t *testing.T) {
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

resource "nftables_map" "dnat_map" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "dnat_map"
  key_type  = "ipv4_addr"
  data_type = "ipv4_addr"
  elements  = {
    "192.168.1.1" = "10.0.0.1"
    "192.168.1.2" = "10.0.0.2"
  }
}`,
				Check: resource.TestCheckResourceAttr("nftables_map.dnat_map", "key_type", "ipv4_addr"),
			},
		},
	})
}
