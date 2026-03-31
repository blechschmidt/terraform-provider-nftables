---
page_title: "nftables_rule Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables rule within a chain.
---

# nftables_rule (Resource)

Manages an nftables rule within a chain. Rules consist of expressions that match packets and perform actions such as accepting, dropping, rejecting, NAT, logging, and more. The `expression` attribute takes a full nftables rule expression string.

## Example Usage

### Basic IP Filtering

```terraform
# Allow traffic from a specific subnet
resource "nftables_rule" "allow_lan" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ip saddr 192.168.1.0/24 accept"
}

# Drop traffic from a specific host
resource "nftables_rule" "block_host" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ip saddr 10.0.0.100 drop"
}

# Allow IPv6 traffic from a prefix
resource "nftables_rule" "allow_ipv6" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ip6 saddr fd00::/64 accept"
}
```

### TCP/UDP Port Filtering

```terraform
# Allow SSH
resource "nftables_rule" "allow_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 accept"
}

# Allow HTTP and HTTPS
resource "nftables_rule" "allow_web" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport { 80, 443 } accept"
}

# Allow DNS (TCP and UDP)
resource "nftables_rule" "allow_dns_udp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "udp dport 53 accept"
}

resource "nftables_rule" "allow_dns_tcp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 53 accept"
}

# Allow a range of ports
resource "nftables_rule" "allow_high_ports" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 8000-8999 accept"
}
```

### ICMP Rules

```terraform
# Allow ICMP echo requests (ping)
resource "nftables_rule" "allow_ping" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "icmp type echo-request accept"
}

# Allow essential ICMPv6 types
resource "nftables_rule" "allow_icmpv6" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept"
}
```

### Connection Tracking (ct)

```terraform
# Allow established and related connections
resource "nftables_rule" "allow_established" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state established,related accept"
}

# Drop invalid connections
resource "nftables_rule" "drop_invalid" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state invalid drop"
}

# Allow new connections only on specific ports
resource "nftables_rule" "allow_new_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state new tcp dport 22 accept"
}
```

### Meta Expressions

```terraform
# Allow loopback traffic
resource "nftables_rule" "allow_loopback" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta iifname \"lo\" accept"
}

# Match by input interface
resource "nftables_rule" "allow_internal" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta iifname \"eth1\" accept"
}

# Match by packet mark
resource "nftables_rule" "marked_accept" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta mark 0x1 accept"
}

# Match by L4 protocol
resource "nftables_rule" "allow_tcp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta l4proto tcp accept"
}
```

### NAT Rules

```terraform
# Source NAT (masquerade) for outgoing traffic
resource "nftables_rule" "masquerade" {
  family     = "ip"
  table      = "nat"
  chain      = "postrouting"
  expression = "oifname \"eth0\" masquerade"
}

# SNAT to a specific address
resource "nftables_rule" "snat" {
  family     = "ip"
  table      = "nat"
  chain      = "postrouting"
  expression = "ip saddr 192.168.1.0/24 oifname \"eth0\" snat to 203.0.113.1"
}

# DNAT (port forwarding) - forward port 8080 to internal server
resource "nftables_rule" "dnat_web" {
  family     = "ip"
  table      = "nat"
  chain      = "prerouting"
  expression = "tcp dport 8080 dnat to 192.168.1.10:80"
}

# Redirect traffic to local port
resource "nftables_rule" "redirect_proxy" {
  family     = "ip"
  table      = "nat"
  chain      = "prerouting"
  expression = "tcp dport 80 redirect to :3128"
}
```

### Counter Rules

```terraform
# Count and accept SSH traffic
resource "nftables_rule" "count_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 counter accept"
}

# Use a named counter
resource "nftables_rule" "named_counter" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 443 counter name https_traffic accept"
}
```

### Rate Limiting

```terraform
# Limit SSH connections to 3 per minute
resource "nftables_rule" "limit_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 ct state new limit rate 3/minute accept"
}

# Limit ICMP to 5 per second with a burst of 10
resource "nftables_rule" "limit_ping" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "icmp type echo-request limit rate 5/second burst 10 packets accept"
}

# Rate limit per source IP
resource "nftables_rule" "limit_per_ip" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 80 meter http_flood { ip saddr limit rate 30/second } accept"
}
```

### Logging

```terraform
# Log dropped packets
resource "nftables_rule" "log_drops" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "log prefix \"nft-drop: \" flags all drop"
}

# Log new SSH connections
resource "nftables_rule" "log_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 ct state new log prefix \"SSH-NEW: \" accept"
}

# Log with rate limiting to avoid log flooding
resource "nftables_rule" "log_limited" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state invalid limit rate 5/minute log prefix \"INVALID: \" drop"
}
```

### Reject Rules

```terraform
# Reject with TCP reset
resource "nftables_rule" "reject_tcp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 113 reject with tcp reset"
}

# Reject with ICMP unreachable
resource "nftables_rule" "reject_icmp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "reject with icmp type port-unreachable"
}

# Reject with ICMPv6 unreachable
resource "nftables_rule" "reject_icmpv6" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta nfproto ipv6 reject with icmpv6 type admin-prohibited"
}
```

### Jump and Goto

```terraform
# Jump to a sub-chain for TCP traffic
resource "nftables_rule" "jump_tcp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta l4proto tcp jump tcp_checks"
}

# Goto another chain (does not return)
resource "nftables_rule" "goto_chain" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ip saddr 10.0.0.0/8 goto internal_rules"
}
```

### Positioning Rules

```terraform
# Insert a rule at a specific position (after the given handle)
resource "nftables_rule" "positioned" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  position   = 42
  expression = "tcp dport 2222 accept"
}
```

## Schema

### Required

- `family` (String) The address family of the parent table. Valid values are `ip`, `ip6`, `inet`, `arp`, `bridge`, and `netdev`.
- `table` (String) The name of the parent table.
- `chain` (String) The name of the parent chain.
- `expression` (String) The nftables rule expression. This is the full rule statement as you would write it in nft syntax (excluding the family/table/chain prefix).

### Optional

- `position` (Number) The handle of an existing rule after which to insert this rule. If not specified, the rule is appended to the end of the chain.

### Read-Only

- `id` (String) The unique identifier for this resource.
- `handle` (Number) The handle number assigned to this rule by nftables. This is a unique numeric identifier within the chain.

## Import

Import is supported using the following syntax:

```shell
terraform import nftables_rule.allow_ssh inet/filter/input/handle/15
```
