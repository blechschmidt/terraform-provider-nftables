---
page_title: "nftables_table Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables table.
---

# nftables_table (Resource)

Manages an nftables table. Tables are the top-level containers in nftables that hold chains, sets, maps, and other objects. Each table belongs to a specific address family (ip, ip6, inet, arp, bridge, or netdev).

## Example Usage

```terraform
resource "nftables_table" "filter" {
  family = "inet"
  name   = "filter"
}

resource "nftables_table" "nat" {
  family = "ip"
  name   = "nat"
}

# A dormant table (rules are not evaluated)
resource "nftables_table" "maintenance" {
  family  = "inet"
  name    = "maintenance"
  dormant = true
}
```

## Schema

### Required

- `family` (String) The address family of the table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `name` (String) The name of the table.

### Optional

- `dormant` (Boolean) If set to `true`, the table is flagged as dormant and its rules are not evaluated. Defaults to `false`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_table.filter inet/filter
```
