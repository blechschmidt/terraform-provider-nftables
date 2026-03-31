---
page_title: "nftables_quota Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables named quota object within a table.
---

# nftables_quota (Resource)

Manages an nftables named quota object within a table. Quotas are stateful objects that track cumulative byte usage and can trigger actions once a threshold is reached. They can operate in two modes: matching until the quota is reached, or matching only after the quota is exceeded (using the `over` flag).

## Example Usage

```terraform
# Quota limiting a host to 1 GB of traffic
resource "nftables_quota" "daily_limit" {
  family = "inet"
  table  = "filter"
  name   = "daily_limit"
  bytes  = 1073741824
}

# Quota that matches after exceeding 500 MB (for logging/dropping)
resource "nftables_quota" "over_limit" {
  family = "inet"
  table  = "filter"
  name   = "over_limit"
  bytes  = 536870912
  over   = true
}

# Quota with pre-set consumed bytes (e.g., after a state restore)
resource "nftables_quota" "restored" {
  family   = "inet"
  table    = "filter"
  name     = "restored"
  bytes    = 10737418240
  consumed = 5368709120
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the quota.
- `bytes` (Number) The quota threshold in bytes.

### Optional

- `over` (Boolean) If `true`, the quota matches only after the threshold has been exceeded. If `false` (default), the quota matches until the threshold is reached.
- `consumed` (Number) The number of bytes already consumed against this quota. Defaults to `0`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_quota.daily_limit inet/filter/daily_limit
```
