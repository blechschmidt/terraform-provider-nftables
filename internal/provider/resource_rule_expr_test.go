package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/blechschmidt/terraform-provider-nftables/internal/testutils"
)

func CompileRegexp(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// These tests verify the v2 JSON expr attribute for the nftables_rule resource.

func TestAccRuleExpr_accept(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "verdict", kind = "accept"}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_tcpDport(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "meta", key = "l4proto", dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0006")},
    {type = "payload", base = "transport", offset = 2, len = 2, dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0000\u0016")},
    {type = "verdict", kind = "accept"}
  ])
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
					testutils.CheckNft(t, ns, []string{"list", "chain", "ip", "filter", "input"}, "dport 22"),
				),
			},
		},
	})
}

func TestAccRuleExpr_counter(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "counter"},
    {type = "verdict", kind = "accept"}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_log(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "log", prefix = "INPUT: ", level = "info"},
    {type = "verdict", kind = "accept"}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_masquerade(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: natBaseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.nat.family
  table  = nftables_table.nat.name
  chain  = nftables_chain.postrouting.name
  expr   = jsonencode([
    {type = "masq"}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_limit(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "limit", rate = 10, unit = "second", burst = 5, limit_type = "pkts"},
    {type = "verdict", kind = "accept"}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_reject(t *testing.T) {
	ns := testutils.CreateTestNamespace(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: baseConfig(ns) + `
resource "nftables_rule" "test" {
  family = nftables_table.test.family
  table  = nftables_table.test.name
  chain  = nftables_chain.input.name
  expr   = jsonencode([
    {type = "reject", reject_type = 0, code = 3}
  ])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

func TestAccRuleExpr_notrack(t *testing.T) {
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
resource "nftables_rule" "test" {
  family = nftables_table.raw.family
  table  = nftables_table.raw.name
  chain  = nftables_chain.prerouting.name
  expr   = jsonencode([{type = "notrack"}])
}`,
				Check: resource.TestCheckResourceAttrSet("nftables_rule.test", "handle"),
			},
		},
	})
}

// Test mutual exclusivity of expression and expr
func TestAccRuleExpr_conflictWithExpression(t *testing.T) {
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
  expression = "accept"
  expr       = jsonencode([{type = "verdict", kind = "accept"}])
}`,
				ExpectError: CompileRegexp("Conflicting attributes"),
			},
		},
	})
}
