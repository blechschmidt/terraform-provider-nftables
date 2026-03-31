---
page_title: "nftables_chain Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables chain within a table.
---

# nftables_chain (Resource)

Manages an nftables chain within a table. Chains hold rules and can be either base chains (attached to a netfilter hook) or regular chains (used as jump/goto targets). Base chains require `type`, `hook`, and `priority` to be set.

## Example Usage

```terraform
# Base chain for filtering incoming traffic
resource "nftables_chain" "input" {
  family   = "inet"
  table    = "filter"
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "drop"
}

# Base chain for forwarding traffic
resource "nftables_chain" "forward" {
  family   = "inet"
  table    = "filter"
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "drop"
}

# Base chain for output traffic
resource "nftables_chain" "output" {
  family   = "inet"
  table    = "filter"
  name     = "output"
  type     = "filter"
  hook     = "output"
  priority = 0
  policy   = "accept"
}

# NAT postrouting chain
resource "nftables_chain" "postrouting" {
  family   = "ip"
  table    = "nat"
  name     = "postrouting"
  type     = "nat"
  hook     = "postrouting"
  priority = 100
}

# Regular (non-base) chain used as a jump target
resource "nftables_chain" "tcp_checks" {
  family = "inet"
  table  = "filter"
  name   = "tcp_checks"
}

# Netdev ingress chain bound to a specific device
resource "nftables_chain" "ingress" {
  family   = "netdev"
  table    = "filter"
  name     = "ingress"
  type     = "filter"
  hook     = "ingress"
  priority = 0
  device   = "eth0"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the chain.

### Optional

- `type` (String) The type of the chain. Required for base chains. Valid values are `filter`, `nat`, and `route`.
- `hook` (String) The netfilter hook to attach to. Required for base chains. Valid values depend on the family and include `prerouting`, `input`, `forward`, `output`, `postrouting`, `ingress`, and `egress`.
- `priority` (Number) The priority of the chain. Required for base chains. Lower values are evaluated first. Common values include `-300` (raw), `-150` (mangle), `0` (filter), `100` (nat), and `300` (security).
- `policy` (String) The default policy for the chain. Valid values are `accept` and `drop`. Only applicable to base chains.
- `device` (String) The network device to bind to. Required for `netdev` family ingress/egress chains.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_chain.input inet/filter/input
```
