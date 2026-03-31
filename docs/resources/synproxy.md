---
page_title: "nftables_synproxy Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables synproxy object within a table.
---

# nftables_synproxy (Resource)

Manages an nftables synproxy object within a table. Synproxy provides SYN flood protection by acting as a proxy for the TCP three-way handshake. The kernel handles the initial SYN/SYN-ACK/ACK exchange and only passes the connection to the backend once the handshake completes, mitigating SYN flood denial-of-service attacks.

## Example Usage

```terraform
# Synproxy for a web server
resource "nftables_synproxy" "web" {
  family    = "inet"
  table     = "filter"
  name      = "web"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}

# Synproxy without TCP options for legacy clients
resource "nftables_synproxy" "legacy" {
  family    = "inet"
  table     = "filter"
  name      = "legacy"
  mss       = 1460
  wscale    = 0
  timestamp = false
  sack_perm = false
}

# Synproxy for SSH protection
resource "nftables_synproxy" "ssh" {
  family    = "inet"
  table     = "filter"
  name      = "ssh"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the synproxy object.
- `mss` (Number) The Maximum Segment Size to advertise during the SYN proxy handshake. Typical value is `1460` for Ethernet.
- `wscale` (Number) The TCP window scale factor to advertise. Valid values are `0` through `14`. A value of `7` is common.

### Optional

- `timestamp` (Boolean) Enable TCP timestamp option in the SYN proxy handshake. Defaults to `false`.
- `sack_perm` (Boolean) Enable TCP selective acknowledgment (SACK) permitted option. Defaults to `false`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_synproxy.web inet/filter/web
```
