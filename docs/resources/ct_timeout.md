---
page_title: "nftables_ct_timeout Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables connection tracking timeout policy object within a table.
---

# nftables_ct_timeout (Resource)

Manages an nftables connection tracking timeout policy object within a table. CT timeout policies allow customizing the connection tracking timeouts for specific protocols and states. This is useful for tuning how long the kernel tracks connections in various states, such as reducing timeouts for short-lived connections or increasing them for long-lived sessions.

## Example Usage

```terraform
# Custom TCP timeout policy with aggressive timeouts
resource "nftables_ct_timeout" "tcp_aggressive" {
  family   = "inet"
  table    = "filter"
  name     = "tcp_aggressive"
  protocol = "tcp"
  l3proto  = "ip"

  policy = {
    established = 300
    close_wait  = 10
    close       = 5
    time_wait   = 30
    syn_sent    = 10
    syn_recv    = 10
    last_ack    = 10
  }
}

# Custom UDP timeout policy
resource "nftables_ct_timeout" "udp_short" {
  family   = "inet"
  table    = "filter"
  name     = "udp_short"
  protocol = "udp"
  l3proto  = "ip"

  policy = {
    unreplied = 15
    replied   = 60
  }
}

# TCP timeout for long-lived connections (e.g., database pools)
resource "nftables_ct_timeout" "tcp_long_lived" {
  family   = "inet"
  table    = "filter"
  name     = "tcp_long_lived"
  protocol = "tcp"
  l3proto  = "ip"

  policy = {
    established = 86400
    close_wait  = 60
    close       = 10
    time_wait   = 120
  }
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the CT timeout object.
- `protocol` (String) The transport layer protocol. Valid values are `tcp` and `udp`.
- `l3proto` (String) The layer 3 protocol family. Valid values are `ip` and `ip6`.
- `policy` (Map of Number) A map of connection state names to timeout values in seconds. For TCP, valid states include `established`, `syn_sent`, `syn_recv`, `fin_wait`, `time_wait`, `close`, `close_wait`, `last_ack`, and `retrans`. For UDP, valid states are `unreplied` and `replied`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_ct_timeout.tcp_aggressive inet/filter/tcp_aggressive
```
