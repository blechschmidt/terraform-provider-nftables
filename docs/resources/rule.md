---
page_title: "nftables_rule Resource - nftables"
subcategory: ""
description: |-
  Manages an nftables rule within a chain.
---

# nftables_rule (Resource)

Manages an nftables rule within a chain. Rules consist of expressions that match packets and perform actions such as accepting, dropping, rejecting, NAT, logging, and more.

Two modes are supported (mutually exclusive):

- **`expression`** (v1): A string in nft syntax, e.g. `"tcp dport 22 accept"`.
- **`expr`** (v2): A JSON-encoded list of netlink VM statement objects. Each statement has a `type` field and type-specific data. Use `jsonencode()` in HCL. This maps directly to the kernel's netlink expression model and supports the full range of nftables operations.

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

### Using `expr` (v2 - JSON netlink VM statements)

```terraform
# Accept TCP dport 22 using raw netlink VM expressions
resource "nftables_rule" "ssh_expr" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = jsonencode([
    {type = "meta", key = "l4proto", dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0006")},
    {type = "payload", base = "transport", offset = 2, len = 2, dreg = 1},
    {type = "cmp", op = "eq", sreg = 1, data = base64encode("\u0000\u0016")},
    {type = "counter"},
    {type = "verdict", kind = "accept"}
  ])
}

# Masquerade using expr
resource "nftables_rule" "masq_expr" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr   = jsonencode([{type = "masq"}])
}

# Rate-limited logging
resource "nftables_rule" "log_expr" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = jsonencode([
    {type = "limit", rate = 5, unit = "second", limit_type = "pkts"},
    {type = "log", prefix = "INPUT: ", level = "info"},
    {type = "verdict", kind = "accept"}
  ])
}
```

### Supported `expr` statement types

| Type | Description | Key Fields |
|------|-------------|------------|
| `payload` | Load bytes from packet header | `base` (link/network/transport), `offset`, `len`, `dreg` |
| `cmp` | Compare register value | `op` (eq/neq/lt/lte/gt/gte), `sreg`, `data` (base64) |
| `meta` | Load packet metadata | `key` (iifname/oifname/l4proto/mark/...), `dreg` |
| `immediate` | Load constant into register | `dreg`, `data` (base64) |
| `bitwise` | Bitwise AND/XOR on register | `sreg`, `dreg`, `len`, `mask` (base64), `xor` (base64) |
| `verdict` | Terminal verdict | `kind` (accept/drop/return/jump/goto), `chain` |
| `counter` | Packet/byte counter | (none) |
| `log` | Log to kernel log | `prefix`, `level`, `group`, `snaplen` |
| `nat` | Source/destination NAT | `nat_type` (snat/dnat), `family`, `reg_addr_min`, `reg_proto_min` |
| `masq` | Masquerade (auto-SNAT) | `random`, `fully_random`, `persistent` |
| `reject` | Reject with ICMP | `reject_type`, `code` |
| `limit` | Rate limiting | `rate`, `unit`, `burst`, `limit_type` (pkts/bytes), `over` |
| `ct` | Conntrack field load | `key` (state/mark/status/...), `dreg`, `direction` |
| `lookup` | Set membership test | `sreg`, `set_name`, `invert` |
| `range` | Range comparison | `op`, `sreg`, `from` (base64), `to` (base64) |
| `redir` | Redirect (local DNAT) | `reg_proto_min`, `reg_proto_max` |
| `queue` | Userspace queue | `num`, `flag` |
| `notrack` | Disable conntrack | (none) |
| `flow_offload` | Hardware flow offload | `name` |
| `fib` | FIB lookup | `dreg`, `flag_saddr/daddr/mark/iif/oif`, `result_oif/oifname/addrtype` |
| `quota` | Byte quota | `bytes`, `over` |
| `connlimit` | Connection limit | `count` |

## Schema

### Required

- `family` (String) The address family of the parent table.
- `table` (String) The name of the parent table.
- `chain` (String) The name of the parent chain.

### Optional (exactly one required)

- `expression` (String) Rule expression in nft syntax (v1). Mutually exclusive with `expr`.
- `expr` (String) JSON-encoded list of netlink VM expressions (v2). Use `jsonencode()`. Mutually exclusive with `expression`.
- `position` (Number) Handle of an existing rule after which to insert this rule.

### Read-Only

- `handle` (Number) The handle number assigned by nftables.

## Import

```shell
terraform import nftables_rule.example family|table|chain|handle
```
