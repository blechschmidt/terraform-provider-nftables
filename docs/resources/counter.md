---
page_title: "nftables_counter Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables named counter object within a table.
---

# nftables_counter (Resource)

Manages an nftables named counter object within a table. Named counters are stateful objects that track the number of packets and bytes matching rules that reference them. Unlike anonymous counters embedded in rules, named counters persist independently and can be referenced by multiple rules.

## Example Usage

```terraform
# Counter for tracking HTTPS traffic
resource "nftables_counter" "https_traffic" {
  family = "inet"
  table  = "filter"
  name   = "https_traffic"
}

# Counter with initial values
resource "nftables_counter" "ssh_traffic" {
  family  = "inet"
  table   = "filter"
  name    = "ssh_traffic"
  packets = 0
  bytes   = 0
}

# Counter for dropped packets
resource "nftables_counter" "dropped" {
  family = "inet"
  table  = "filter"
  name   = "dropped"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the counter.

### Optional

- `packets` (Number) Initial packet count. Defaults to `0`.
- `bytes` (Number) Initial byte count. Defaults to `0`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_counter.https_traffic inet/filter/https_traffic
```
