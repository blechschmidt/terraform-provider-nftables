---
page_title: "nftables_map Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables named map within a table.
---

# nftables_map (Resource)

Manages an nftables named map within a table. Maps associate keys with values and are used in rules to perform lookups, such as translating source addresses to NAT targets or mapping interfaces to verdict actions. Maps extend set functionality by pairing each element with a corresponding data value.

## Example Usage

```terraform
# Verdict map for per-interface policy
resource "nftables_map" "iface_policy" {
  family    = "inet"
  table     = "filter"
  name      = "iface_policy"
  key_type  = "ifname"
  data_type = "verdict"

  elements = [
    "\"eth0\" : accept",
    "\"eth1\" : drop",
    "\"eth2\" : jump tcp_checks",
  ]
}

# NAT map for port-based DNAT
resource "nftables_map" "port_forward" {
  family    = "ip"
  table     = "nat"
  name      = "port_forward"
  key_type  = "inet_service"
  data_type = "ipv4_addr . inet_service"

  elements = [
    "80 : 192.168.1.10 . 80",
    "443 : 192.168.1.10 . 443",
    "8080 : 192.168.1.20 . 8080",
  ]
}

# Map source IPs to marks
resource "nftables_map" "ip_to_mark" {
  family    = "inet"
  table     = "filter"
  name      = "ip_to_mark"
  key_type  = "ipv4_addr"
  data_type = "mark"
  flags     = ["interval"]

  elements = [
    "192.168.1.0/24 : 0x1",
    "192.168.2.0/24 : 0x2",
    "10.0.0.0/8 : 0x3",
  ]

  comment = "Assign packet marks based on source network"
}

# Simple IP to IP mapping for SNAT
resource "nftables_map" "snat_map" {
  family    = "ip"
  table     = "nat"
  name      = "snat_map"
  key_type  = "ipv4_addr"
  data_type = "ipv4_addr"

  elements = [
    "192.168.1.10 : 203.0.113.1",
    "192.168.1.20 : 203.0.113.2",
  ]
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the map.
- `key_type` (String) The data type for map keys. Common values are `ipv4_addr`, `ipv6_addr`, `inet_service`, `inet_proto`, `ether_addr`, `mark`, and `ifname`.
- `data_type` (String) The data type for map values. Accepts the same types as `key_type`, plus `verdict` for verdict maps. Concatenated types use ` . ` as a separator.

### Optional

- `flags` (List of String) Map flags. Valid values are `constant`, `interval`, `timeout`, and `dynamic`.
- `comment` (String) A human-readable comment for the map.
- `elements` (List of String) Static elements in `key : value` format.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_map.port_forward ip/nat/port_forward
```
