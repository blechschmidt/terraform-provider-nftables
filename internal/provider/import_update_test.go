package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

// ============================================================================
// Import tests for resources missing ImportState coverage
// ============================================================================

func TestAccQuotaResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_quota" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "import_quota"
  bytes  = 1000000
}`,
			},
			{
				ResourceName:  "nftables_quota.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_quota",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"bytes", "over", "consumed"},
			},
		},
	})
}

func TestAccLimitResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_limit" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  name   = "import_limit"
  rate   = 100
  unit   = "second"
}`,
			},
			{
				ResourceName:  "nftables_limit.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_limit",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"rate", "unit", "burst", "type", "over"},
			},
		},
	})
}

func TestAccCtHelperResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_ct_helper" "test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "import_helper"
  helper   = "ftp"
  protocol = "tcp"
  l3proto  = "ip"
}`,
			},
			{
				ResourceName:  "nftables_ct_helper.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_helper",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"helper", "protocol", "l3proto"},
			},
		},
	})
}

func TestAccCtTimeoutResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_ct_timeout" "test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "import_timeout"
  protocol = "tcp"
  l3proto  = "ip"
  policy   = { "5" = 3600 }
}`,
			},
			{
				ResourceName:  "nftables_ct_timeout.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_timeout",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"protocol", "l3proto", "policy"},
			},
		},
	})
}

func TestAccCtExpectationResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_ct_expectation" "test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "import_expect"
  protocol = "udp"
  l3proto  = "ip"
  dport    = 5060
  timeout  = 30000
  size     = 8
}`,
			},
			{
				ResourceName:  "nftables_ct_expectation.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_expect",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"protocol", "l3proto", "dport", "timeout", "size"},
			},
		},
	})
}

func TestAccSynproxyResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: statefulBaseConfig(ns) + `
resource "nftables_synproxy" "test" {
  family    = nftables_table.test.family
  table     = nftables_table.test.name
  name      = "import_synproxy"
  mss       = 1460
  wscale    = 7
}`,
			},
			{
				ResourceName:  "nftables_synproxy.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_synproxy",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"mss", "wscale", "timestamp", "sack_perm"},
			},
		},
	})
}

func TestAccFlowtableResource_import(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)
	testutils.RunInNamespace(t, ns, "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
	testutils.RunInNamespace(t, ns, "ip", "link", "set", "veth0", "up")
	testutils.RunInNamespace(t, ns, "ip", "link", "set", "veth1", "up")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testutils.ProviderConfig(ns) + `
resource "nftables_table" "test" {
  family = "ip"
  name   = "filter"
}
resource "nftables_flowtable" "test" {
  family   = nftables_table.test.family
  table    = nftables_table.test.name
  name     = "import_ft"
  hook     = "ingress"
  priority = 0
  devices  = ["veth0"]
}`,
			},
			{
				ResourceName:  "nftables_flowtable.test",
				ImportState:   true,
				ImportStateId: "ip|filter|import_ft",
				ImportStateVerifyIdentifierAttribute: "name",
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"hook", "priority", "devices"},
			},
		},
	})
}
