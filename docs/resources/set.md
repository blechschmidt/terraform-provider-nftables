---
page_title: "nftables_set Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables named set within a table.
---

# nftables_set (Resource)

Manages an nftables named set within a table. Sets are collections of elements of the same data type that can be referenced in rules for efficient matching. Sets support features like timeouts, size limits, and automatic element merging for interval sets.

## Example Usage

```terraform
# Simple IP address set for a blocklist
resource "nftables_set" "blocklist" {
  family = "inet"
  table  = "filter"
  name   = "blocklist"
  type   = "ipv4_addr"

  elements = [
    "192.168.1.100",
    "10.0.0.50",
  ]
}

# Set with timeout for dynamic entries (e.g., rate-limited hosts)
resource "nftables_set" "rate_limited" {
  family  = "inet"
  table   = "filter"
  name    = "rate_limited"
  type    = "ipv4_addr"
  flags   = ["timeout"]
  timeout = 300
}

# Interval set for network ranges with auto-merge
resource "nftables_set" "trusted_nets" {
  family     = "inet"
  table      = "filter"
  name       = "trusted_nets"
  type       = "ipv4_addr"
  flags      = ["interval"]
  auto_merge = true

  elements = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
  ]
}

# Port set
resource "nftables_set" "allowed_ports" {
  family = "inet"
  table  = "filter"
  name   = "allowed_ports"
  type   = "inet_service"

  elements = [
    "22",
    "80",
    "443",
    "8080",
  ]
}

# Set with per-element counters
resource "nftables_set" "monitored_hosts" {
  family  = "inet"
  table   = "filter"
  name    = "monitored_hosts"
  type    = "ipv4_addr"
  counter = true
  comment = "Hosts with per-element packet counters"

  elements = [
    "10.0.0.1",
    "10.0.0.2",
  ]
}

# Concatenated type set (IP + port)
resource "nftables_set" "allowed_services" {
  family = "inet"
  table  = "filter"
  name   = "allowed_services"
  type   = "ipv4_addr . inet_service"

  elements = [
    "192.168.1.10 . 80",
    "192.168.1.10 . 443",
    "192.168.1.20 . 22",
  ]
}

# Set with size limit and hash policy
resource "nftables_set" "limited_set" {
  family = "inet"
  table  = "filter"
  name   = "limited_set"
  type   = "ipv4_addr"
  size   = 65535
  policy = "memory"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the set.
- `type` (String) The data type of set elements. Common values are `ipv4_addr`, `ipv6_addr`, `inet_service`, `inet_proto`, `ether_addr`, `mark`, and `ifname`. Concatenated types use ` . ` as a separator (e.g., `ipv4_addr . inet_service`).

### Optional

- `flags` (List of String) Set flags. Valid values are `constant`, `interval`, `timeout`, and `dynamic`.
- `timeout` (Number) Default timeout in seconds for set elements. Requires the `timeout` flag.
- `size` (Number) Maximum number of elements in the set.
- `policy` (String) The set storage policy. Valid values are `performance` (hash-based, default) and `memory` (rbtree-based, lower memory usage).
- `auto_merge` (Boolean) Automatically merge overlapping or adjacent intervals. Only applicable to sets with the `interval` flag.
- `counter` (Boolean) Enable per-element packet and byte counters.
- `comment` (String) A human-readable comment for the set.
- `elements` (List of String) Static elements to include in the set.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_set.blocklist inet/filter/blocklist
```
