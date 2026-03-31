---
page_title: "nftables_limit Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables named limit object within a table.
---

# nftables_limit (Resource)

Manages an nftables named limit object within a table. Limits are stateful objects that implement rate limiting using a token bucket algorithm. They can limit by packets per time unit or by bytes per time unit, and can be referenced by multiple rules.

## Example Usage

```terraform
# Limit to 25 packets per minute (e.g., for SSH)
resource "nftables_limit" "ssh_rate" {
  family = "inet"
  table  = "filter"
  name   = "ssh_rate"
  rate   = 25
  unit   = "minute"
  type   = "packets"
}

# Limit to 5 packets per second with a burst of 10
resource "nftables_limit" "icmp_rate" {
  family = "inet"
  table  = "filter"
  name   = "icmp_rate"
  rate   = 5
  unit   = "second"
  burst  = 10
  type   = "packets"
}

# Byte-based limit for bandwidth throttling (1 MB/s)
resource "nftables_limit" "bandwidth" {
  family = "inet"
  table  = "filter"
  name   = "bandwidth"
  rate   = 1048576
  unit   = "second"
  type   = "bytes"
  burst  = 2097152
}

# Inverse limit - matches when rate is exceeded (for dropping)
resource "nftables_limit" "flood_detect" {
  family = "inet"
  table  = "filter"
  name   = "flood_detect"
  rate   = 100
  unit   = "second"
  type   = "packets"
  over   = true
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the limit.
- `rate` (Number) The rate value. Interpreted as packets or bytes depending on `type`.
- `unit` (String) The time unit for the rate. Valid values are `second`, `minute`, `hour`, `day`, and `week`.

### Optional

- `burst` (Number) The burst allowance. Permits temporary spikes above the rate limit. Interpreted as packets or bytes depending on `type`. Defaults to `5` for packet limits and `0` for byte limits.
- `type` (String) The rate limit type. Valid values are `packets` (default) and `bytes`.
- `over` (Boolean) If `true`, the limit matches when the rate is exceeded rather than when traffic is under the limit. Useful for dropping excess traffic. Defaults to `false`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_limit.ssh_rate inet/filter/ssh_rate
```
