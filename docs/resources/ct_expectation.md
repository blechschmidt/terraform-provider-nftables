---
page_title: "nftables_ct_expectation Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables connection tracking expectation object within a table.
---

# nftables_ct_expectation (Resource)

Manages an nftables connection tracking expectation object within a table. CT expectations define parameters for expected secondary connections that protocols create dynamically. This is used by protocols like FTP and SIP where a control connection negotiates parameters for subsequent data connections.

## Example Usage

```terraform
# Expectation for FTP data connections
resource "nftables_ct_expectation" "ftp_data" {
  family   = "inet"
  table    = "filter"
  name     = "ftp_data"
  protocol = "tcp"
  l3proto  = "ip"
  dport    = 20
  timeout  = 300
  size     = 8
}

# Expectation for SIP RTP streams
resource "nftables_ct_expectation" "sip_rtp" {
  family   = "inet"
  table    = "filter"
  name     = "sip_rtp"
  protocol = "udp"
  l3proto  = "ip"
  dport    = 5060
  timeout  = 180
  size     = 16
}

# Expectation for H.323 media channels
resource "nftables_ct_expectation" "h323_media" {
  family   = "inet"
  table    = "filter"
  name     = "h323_media"
  protocol = "tcp"
  l3proto  = "ip"
  dport    = 1720
  timeout  = 240
  size     = 4
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `name` (String) The name of the CT expectation object.
- `protocol` (String) The transport layer protocol. Valid values are `tcp` and `udp`.
- `l3proto` (String) The layer 3 protocol family. Valid values are `ip` and `ip6`.
- `dport` (Number) The expected destination port for the secondary connection.
- `timeout` (Number) The timeout in seconds for the expectation.
- `size` (Number) The maximum number of concurrent expectations.

### Read-Only

- `id` (String) The unique identifier for this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_ct_expectation.ftp_data inet/filter/ftp_data
```
