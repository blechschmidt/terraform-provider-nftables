---
page_title: "nftables_secmark Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables secmark object within a table.
---

# nftables_secmark (Resource)

Manages an nftables secmark object within a table. Secmarks are used to assign SELinux security labels to packets and connections. When a packet matches a rule that sets a secmark, the associated SELinux security context is applied, enabling mandatory access control policies to govern network traffic.

## Example Usage

```terraform
# Secmark for HTTP server traffic
resource "nftables_secmark" "http" {
  family  = "inet"
  table   = "filter"
  name    = "http"
  context = "system_u:object_r:httpd_packet_t:s0"
}

# Secmark for SSH traffic
resource "nftables_secmark" "ssh" {
  family  = "inet"
  table   = "filter"
  name    = "ssh"
  context = "system_u:object_r:ssh_packet_t:s0"
}

# Secmark for DNS traffic
resource "nftables_secmark" "dns" {
  family  = "inet"
  table   = "filter"
  name    = "dns"
  context = "system_u:object_r:dns_packet_t:s0"
}

# Secmark for database traffic
resource "nftables_secmark" "database" {
  family  = "inet"
  table   = "filter"
  name    = "database"
  context = "system_u:object_r:postgresql_packet_t:s0"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the secmark object.
- `context` (String) The SELinux security context string to apply to matching packets. The format is `user:role:type:level` (e.g., `system_u:object_r:httpd_packet_t:s0`).

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_secmark.http inet/filter/http
```
