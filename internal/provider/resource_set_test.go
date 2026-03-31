package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/terraform-providers/terraform-provider-nftables/internal/testutils"
)

func TestAccSetResource_basic(t *testing.T) {
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

resource "nftables_set" "allowed" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "allowed_ips"
  type   = "ipv4_addr"
  elements = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_set.allowed", "name", "allowed_ips"),
					resource.TestCheckResourceAttr("nftables_set.allowed", "type", "ipv4_addr"),
					testutils.CheckNft(t, ns, []string{"list", "set", "ip", "filter", "allowed_ips"}, "allowed_ips"),
				),
			},
		},
	})
}

func TestAccSetResource_inetService(t *testing.T) {
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

resource "nftables_set" "ports" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "allowed_ports"
  type     = "inet_service"
  elements = ["22", "80", "443"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.ports", "name", "allowed_ports"),
			},
		},
	})
}

func TestAccSetResource_interval(t *testing.T) {
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

resource "nftables_set" "ranges" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "ip_ranges"
  type     = "ipv4_addr"
  flags    = ["interval"]
  elements = ["192.168.0.0/24", "10.0.0.0/8"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.ranges", "name", "ip_ranges"),
			},
		},
	})
}

func TestAccSetResource_withCounter(t *testing.T) {
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

resource "nftables_set" "counted" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "counted_ips"
  type     = "ipv4_addr"
  counter  = true
  elements = ["10.0.0.1"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.counted", "counter", "true"),
			},
		},
	})
}

func TestAccSetResource_ipv6(t *testing.T) {
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

resource "nftables_set" "v6addrs" {
  family   = nftables_table.test6.family
  table    = nftables_table.test6.name
  name     = "blocked_v6"
  type     = "ipv6_addr"
  elements = ["::1", "fe80::1"]
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.v6addrs", "type", "ipv6_addr"),
			},
		},
	})
}

func TestAccSetResource_empty(t *testing.T) {
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

resource "nftables_set" "empty" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "empty_set"
  type   = "ipv4_addr"
}`,
				Check: resource.TestCheckResourceAttr("nftables_set.empty", "name", "empty_set"),
			},
		},
	})
}
