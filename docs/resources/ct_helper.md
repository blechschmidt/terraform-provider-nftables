---
page_title: "nftables_ct_helper Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables connection tracking helper object within a table.
---

# nftables_ct_helper (Resource)

Manages an nftables connection tracking helper object within a table. CT helpers enable application-layer gateway (ALG) functionality for protocols that use dynamic secondary connections, such as FTP, SIP, TFTP, and others. The helper object must be assigned to connections via a rule using `ct helper set`.

## Example Usage

```terraform
# FTP connection tracking helper
resource "nftables_ct_helper" "ftp" {
  family   = "inet"
  table    = "filter"
  name     = "ftp"
  helper   = "ftp"
  protocol = "tcp"
  l3proto  = "ip"
}

# SIP connection tracking helper
resource "nftables_ct_helper" "sip" {
  family   = "inet"
  table    = "filter"
  name     = "sip"
  helper   = "sip"
  protocol = "udp"
  l3proto  = "ip"
}

# TFTP connection tracking helper
resource "nftables_ct_helper" "tftp" {
  family   = "inet"
  table    = "filter"
  name     = "tftp"
  helper   = "tftp"
  protocol = "udp"
  l3proto  = "ip"
}

# H.323 connection tracking helper for IPv6
resource "nftables_ct_helper" "h323_v6" {
  family   = "inet"
  table    = "filter"
  name     = "h323_v6"
  helper   = "h323"
  protocol = "tcp"
  l3proto  = "ip6"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the CT helper object.
- `helper` (String) The connection tracking helper type. Common values are `ftp`, `sip`, `tftp`, `h323`, `irc`, `pptp`, `snmp`, `amanda`, and `netbios-ns`.
- `protocol` (String) The transport layer protocol. Valid values are `tcp` and `udp`.
- `l3proto` (String) The layer 3 protocol family. Valid values are `ip` and `ip6`.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_ct_helper.ftp inet/filter/ftp
```
