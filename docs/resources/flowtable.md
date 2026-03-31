---
page_title: "nftables_flowtable Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables flowtable for hardware-offloaded connection tracking.
---

# nftables_flowtable (Resource)

Manages an nftables flowtable for hardware-offloaded connection tracking. Flowtables allow the kernel to bypass the normal packet processing path for established connections, significantly improving forwarding performance. Connections are offloaded to the flowtable after initial classification by nftables rules.

## Example Usage

```terraform
# Flowtable for offloading forwarded traffic between LAN and WAN
resource "nftables_flowtable" "offload" {
  family   = "inet"
  table    = "filter"
  name     = "offload"
  hook     = "ingress"
  priority = 0
  devices  = ["eth0", "eth1"]
}

# Flowtable for a multi-interface router
resource "nftables_flowtable" "router_offload" {
  family   = "inet"
  table    = "filter"
  name     = "router_offload"
  hook     = "ingress"
  priority = -100
  devices  = ["eth0", "eth1", "eth2", "wlan0"]
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, and `inet`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the flowtable.
- `hook` (String) The netfilter hook to attach to. Must be `ingress`.
- `priority` (Number) The priority of the flowtable. Lower values are evaluated first.
- `devices` (List of String) The list of network devices to offload traffic from.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_flowtable.offload inet/filter/offload
```
