package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/terraform-providers/terraform-provider-nftables/internal/testutils"
)

func statefulBaseConfig(ns string) string {
	return testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
`
}

// --- Counter tests ---

func TestAccCounterResource_basic(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_counter" "http" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "http_counter"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_counter.http", "name", "http_counter"),
					resource.TestCheckResourceAttr("nftables_counter.http", "packets", "0"),
					resource.TestCheckResourceAttr("nftables_counter.http", "bytes", "0"),
				),
			},
		},
	})
}

// --- Quota tests ---

func TestAccQuotaResource_basic(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_quota" "bandwidth" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "bandwidth_limit"
  bytes  = 1073741824
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_quota.bandwidth", "name", "bandwidth_limit"),
					resource.TestCheckResourceAttr("nftables_quota.bandwidth", "bytes", "1073741824"),
				),
			},
		},
	})
}

func TestAccQuotaResource_over(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_quota" "over_test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "over_quota"
  bytes  = 5242880
  over   = true
}`,
				Check: resource.TestCheckResourceAttr("nftables_quota.over_test", "over", "true"),
			},
		},
	})
}

// --- Limit tests ---

func TestAccLimitResource_packets(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_limit" "rate_limit" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "rate_limit"
  rate   = 100
  unit   = "second"
  burst  = 50
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_limit.rate_limit", "name", "rate_limit"),
					resource.TestCheckResourceAttr("nftables_limit.rate_limit", "rate", "100"),
					resource.TestCheckResourceAttr("nftables_limit.rate_limit", "unit", "second"),
				),
			},
		},
	})
}

func TestAccLimitResource_bytes(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_limit" "byte_limit" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "byte_limit"
  rate   = 1048576
  unit   = "second"
  type   = "bytes"
}`,
				Check: resource.TestCheckResourceAttr("nftables_limit.byte_limit", "type", "bytes"),
			},
		},
	})
}

// --- CT Helper tests ---

func TestAccCtHelperResource_ftp(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_ct_helper" "ftp" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "ftp_helper"
  helper   = "ftp"
  protocol = "tcp"
  l3proto  = "ip"
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_ct_helper.ftp", "helper", "ftp"),
					resource.TestCheckResourceAttr("nftables_ct_helper.ftp", "protocol", "tcp"),
				),
			},
		},
	})
}

// --- Synproxy tests ---

func TestAccSynproxyResource_basic(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_synproxy" "http" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "http_synproxy"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nftables_synproxy.http", "mss", "1460"),
					resource.TestCheckResourceAttr("nftables_synproxy.http", "wscale", "7"),
					resource.TestCheckResourceAttr("nftables_synproxy.http", "timestamp", "true"),
					resource.TestCheckResourceAttr("nftables_synproxy.http", "sack_perm", "true"),
				),
			},
		},
	})
}
