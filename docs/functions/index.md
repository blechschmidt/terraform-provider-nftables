---
page_title: "Provider Functions - nftables"
subcategory: ""
description: |-
  Terraform provider functions for composing nftables rule expressions.
---

# Provider Functions

The nftables provider includes 64 provider-defined functions for composing nftables rule expressions in a type-safe, declarative way. Each function returns a JSON-encoded expression list that can be combined using `combine()` and passed to the `expr` attribute of `nftables_rule`.

All functions are called with the `provider::nftables::` prefix.

## How It Works

Each function produces a JSON-encoded list of netlink VM expressions. The `combine()` function merges multiple expression lists into a single list suitable for the `expr` attribute on `nftables_rule`.

```terraform
resource "nftables_rule" "allow_ssh" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

---

## Combiner

### `combine`

Combine multiple expression lists into a single rule expression. This is the primary function used to compose rules from individual matcher, action, and verdict functions.

#### Example Usage

```terraform
resource "nftables_rule" "web_traffic" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("eth0"),
    provider::nftables::match_tcp_dport(443),
    provider::nftables::match_ct_state(["new", "established"]),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
combine(parts...) string
```

#### Arguments

- `parts` (variadic string) JSON expression lists to combine. Each argument is typically the return value of another provider function.

---

## Verdicts

Verdict functions determine the final disposition of a packet.

### `accept`

Accept the packet, allowing it to continue through the network stack.

#### Example Usage

```terraform
resource "nftables_rule" "accept_loopback" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
accept() string
```

### `drop`

Drop the packet silently, discarding it without sending any response.

#### Example Usage

```terraform
resource "nftables_rule" "drop_invalid" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["invalid"]),
    provider::nftables::drop(),
  )
}
```

#### Signature

```text
drop() string
```

### `return_verdict`

Return from the current chain, resuming evaluation in the calling chain.

#### Example Usage

```terraform
resource "nftables_rule" "return_from_subchain" {
  family = "inet"
  table  = "filter"
  chain  = "tcp_checks"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_flags("syn"),
    provider::nftables::return_verdict(),
  )
}
```

#### Signature

```text
return_verdict() string
```

### `jump`

Jump to another chain. After the target chain completes, evaluation continues after this rule.

#### Example Usage

```terraform
resource "nftables_rule" "jump_to_tcp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_l4proto("tcp"),
    provider::nftables::jump("tcp_checks"),
  )
}
```

#### Signature

```text
jump(chain) string
```

#### Arguments

- `chain` (string) Target chain name.

### `goto_chain`

Go to another chain. Unlike `jump`, control does not return to the calling chain.

#### Example Usage

```terraform
resource "nftables_rule" "goto_logging" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.0.0/8"),
    provider::nftables::goto_chain("log_and_drop"),
  )
}
```

#### Signature

```text
goto_chain(chain) string
```

#### Arguments

- `chain` (string) Target chain name.

---

## Actions

Action functions perform operations on matching packets (counting, logging, NAT, etc.).

### `counter`

Add an inline packet/byte counter to the rule.

#### Example Usage

```terraform
resource "nftables_rule" "counted_accept" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
counter() string
```

### `log`

Log matching packets with a prefix and syslog level.

#### Example Usage

```terraform
resource "nftables_rule" "log_dropped" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["invalid"]),
    provider::nftables::log("INVALID_DROP: ", "warn"),
    provider::nftables::drop(),
  )
}
```

#### Signature

```text
log(prefix, level) string
```

#### Arguments

- `prefix` (string) Log prefix string prepended to each log entry.
- `level` (string) Syslog level. Valid values: `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug`.

### `limit`

Rate limit matching packets.

#### Example Usage

```terraform
resource "nftables_rule" "rate_limit_ping" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit(10, "second"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
limit(rate, unit) string
```

#### Arguments

- `rate` (number) Rate value (packets per time unit).
- `unit` (string) Time unit. Valid values: `second`, `minute`, `hour`, `day`, `week`.

### `limit_burst`

Rate limit matching packets with a burst allowance.

#### Example Usage

```terraform
resource "nftables_rule" "rate_limit_burst" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::limit_burst(100, "second", 50),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
limit_burst(rate, unit, burst) string
```

#### Arguments

- `rate` (number) Rate value (packets per time unit).
- `unit` (string) Time unit. Valid values: `second`, `minute`, `hour`, `day`, `week`.
- `burst` (number) Burst value -- number of packets allowed to exceed the rate.

### `limit_bytes`

Rate limit by bytes per time unit.

#### Example Usage

```terraform
resource "nftables_rule" "bandwidth_limit" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::limit_bytes(1048576, "second"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
limit_bytes(rate, unit) string
```

#### Arguments

- `rate` (number) Rate in bytes per time unit.
- `unit` (string) Time unit. Valid values: `second`, `minute`, `hour`, `day`, `week`.

### `reject`

Reject the packet with the default ICMP error (port unreachable).

#### Example Usage

```terraform
resource "nftables_rule" "reject_default" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_dport(53),
    provider::nftables::reject(),
  )
}
```

#### Signature

```text
reject() string
```

### `reject_tcp_reset`

Reject TCP connections with a TCP RST packet.

#### Example Usage

```terraform
resource "nftables_rule" "reject_tcp_rst" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(8080),
    provider::nftables::reject_tcp_reset(),
  )
}
```

#### Signature

```text
reject_tcp_reset() string
```

### `reject_icmp`

Reject with a specific ICMP error code (IPv4).

#### Example Usage

```terraform
resource "nftables_rule" "reject_admin" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("192.168.1.0/24"),
    provider::nftables::reject_icmp("admin-prohibited"),
  )
}
```

#### Signature

```text
reject_icmp(code) string
```

#### Arguments

- `code` (string) ICMP reject code. Valid values: `port-unreachable`, `host-unreachable`, `net-unreachable`, `admin-prohibited`, etc.

### `reject_icmpv6`

Reject with a specific ICMPv6 error code.

#### Example Usage

```terraform
resource "nftables_rule" "reject_v6" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_saddr("fd00::/8"),
    provider::nftables::reject_icmpv6("admin-prohibited"),
  )
}
```

#### Signature

```text
reject_icmpv6(code) string
```

#### Arguments

- `code` (string) ICMPv6 reject code. Valid values: `no-route`, `admin-prohibited`, `addr-unreachable`, `port-unreachable`.

### `reject_icmpx`

Reject with an ICMPx code, suitable for the `inet` (dual-stack) family.

#### Example Usage

```terraform
resource "nftables_rule" "reject_inet" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(9999),
    provider::nftables::reject_icmpx("admin-prohibited"),
  )
}
```

#### Signature

```text
reject_icmpx(code) string
```

#### Arguments

- `code` (string) ICMPx reject code. Valid values: `port-unreachable`, `admin-prohibited`, `no-route`, `host-unreachable`.

### `masquerade`

Masquerade outgoing packets (automatic source NAT using the outgoing interface address).

#### Example Usage

```terraform
resource "nftables_rule" "masq" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade(),
  )
}
```

#### Signature

```text
masquerade() string
```

### `masquerade_random`

Masquerade with random source port selection.

#### Example Usage

```terraform
resource "nftables_rule" "masq_random" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_random(),
  )
}
```

#### Signature

```text
masquerade_random() string
```

### `masquerade_persistent`

Masquerade with persistent mapping, ensuring the same source address/port is used for all connections from the same origin.

#### Example Usage

```terraform
resource "nftables_rule" "masq_persistent" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_persistent(),
  )
}
```

#### Signature

```text
masquerade_persistent() string
```

### `masquerade_fully_random`

Masquerade with fully randomized source port selection.

#### Example Usage

```terraform
resource "nftables_rule" "masq_fully_random" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::masquerade_fully_random(),
  )
}
```

#### Signature

```text
masquerade_fully_random() string
```

### `snat`

Source NAT to a specific address.

#### Example Usage

```terraform
resource "nftables_rule" "snat_rule" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth0"),
    provider::nftables::snat("203.0.113.1"),
  )
}
```

#### Signature

```text
snat(addr) string
```

#### Arguments

- `addr` (string) Target IPv4 address for source NAT.

### `snat_port`

Source NAT to a specific address and port.

#### Example Usage

```terraform
resource "nftables_rule" "snat_port_rule" {
  family = "ip"
  table  = "nat"
  chain  = "postrouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::snat_port("203.0.113.1", 8080),
  )
}
```

#### Signature

```text
snat_port(addr, port) string
```

#### Arguments

- `addr` (string) Target IPv4 address.
- `port` (number) Target port number.

### `dnat`

Destination NAT to a specific address.

#### Example Usage

```terraform
resource "nftables_rule" "dnat_rule" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::dnat("10.0.0.100"),
  )
}
```

#### Signature

```text
dnat(addr) string
```

#### Arguments

- `addr` (string) Target IPv4 address for destination NAT.

### `dnat_port`

Destination NAT to a specific address and port.

#### Example Usage

```terraform
resource "nftables_rule" "dnat_port_rule" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::dnat_port("10.0.0.100", 8443),
  )
}
```

#### Signature

```text
dnat_port(addr, port) string
```

#### Arguments

- `addr` (string) Target IPv4 address.
- `port` (number) Target port number.

### `redirect`

Redirect traffic to a local port (DNAT to localhost).

#### Example Usage

```terraform
resource "nftables_rule" "redirect_rule" {
  family = "ip"
  table  = "nat"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(80),
    provider::nftables::redirect(3128),
  )
}
```

#### Signature

```text
redirect(port) string
```

#### Arguments

- `port` (number) Target local port number.

### `notrack`

Disable connection tracking for matching packets. Typically used in the raw table.

#### Example Usage

```terraform
resource "nftables_rule" "notrack_dns" {
  family = "ip"
  table  = "raw"
  chain  = "prerouting"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_dport(53),
    provider::nftables::notrack(),
  )
}
```

#### Signature

```text
notrack() string
```

### `flow_offload`

Offload matching flows to a named flowtable for hardware/software fast-path processing.

#### Example Usage

```terraform
resource "nftables_rule" "offload" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["established"]),
    provider::nftables::flow_offload("fastpath"),
  )
}
```

#### Signature

```text
flow_offload(name) string
```

#### Arguments

- `name` (string) Name of the flowtable to offload to.

### `queue`

Queue matching packets to a userspace program via NFQUEUE.

#### Example Usage

```terraform
resource "nftables_rule" "queue_rule" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::queue(0),
  )
}
```

#### Signature

```text
queue(num) string
```

#### Arguments

- `num` (number) Queue number (0-65535).

---

## Setters

Setter functions modify packet metadata or connection tracking fields.

### `set_mark`

Set the packet mark (nfmark/fwmark).

#### Example Usage

```terraform
resource "nftables_rule" "mark_traffic" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("10.0.1.0/24"),
    provider::nftables::set_mark(100),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
set_mark(mark) string
```

#### Arguments

- `mark` (number) Mark value to set on the packet.

### `set_ct_mark`

Set the conntrack mark on the connection.

#### Example Usage

```terraform
resource "nftables_rule" "ct_mark_traffic" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["new"]),
    provider::nftables::match_oifname("eth1"),
    provider::nftables::set_ct_mark(42),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
set_ct_mark(mark) string
```

#### Arguments

- `mark` (number) Conntrack mark value to set.

### `set_priority`

Set the packet priority (TC class).

#### Example Usage

```terraform
resource "nftables_rule" "set_prio" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::set_priority(1),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
set_priority(priority) string
```

#### Arguments

- `priority` (number) Priority value to set.

### `set_nftrace`

Enable nftrace debugging for matching packets. Use with `nft monitor trace` for troubleshooting.

#### Example Usage

```terraform
resource "nftables_rule" "trace_debug" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("192.168.1.100"),
    provider::nftables::set_nftrace(),
  )
}
```

#### Signature

```text
set_nftrace() string
```

---

## IPv4 Matchers

Functions for matching IPv4 header fields. Use in tables with `ip` or `inet` family.

### `match_ip_saddr`

Match the IPv4 source address. Supports both single addresses and CIDR notation.

#### Example Usage

```terraform
resource "nftables_rule" "match_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_saddr("192.168.1.0/24"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip_saddr(addr) string
```

#### Arguments

- `addr` (string) IPv4 address or CIDR (e.g., `192.168.1.1` or `10.0.0.0/8`).

### `match_ip_daddr`

Match the IPv4 destination address. Supports both single addresses and CIDR notation.

#### Example Usage

```terraform
resource "nftables_rule" "match_dst" {
  family = "inet"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_daddr("8.8.8.8"),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip_daddr(addr) string
```

#### Arguments

- `addr` (string) IPv4 address or CIDR.

### `match_ip_protocol`

Match the IP protocol field.

#### Example Usage

```terraform
resource "nftables_rule" "match_proto" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_protocol("icmp"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip_protocol(proto) string
```

#### Arguments

- `proto` (string) Protocol name: `tcp`, `udp`, `icmp`, `sctp`, `dccp`, `gre`, `esp`, `ah`, etc.

### `match_ip_ttl`

Match the IP Time-To-Live field.

#### Example Usage

```terraform
resource "nftables_rule" "match_ttl" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_ttl(1),
    provider::nftables::drop(),
  )
}
```

#### Signature

```text
match_ip_ttl(ttl) string
```

#### Arguments

- `ttl` (number) TTL value (0-255).

### `match_ip_length`

Match the IP total length field.

#### Example Usage

```terraform
resource "nftables_rule" "match_length" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip_length(1500),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip_length(length) string
```

#### Arguments

- `length` (number) IP total length value (0-65535).

---

## IPv6 Matchers

Functions for matching IPv6 header fields. Use in tables with `ip6` or `inet` family.

### `match_ip6_saddr`

Match the IPv6 source address. Supports both single addresses and CIDR notation.

#### Example Usage

```terraform
resource "nftables_rule" "match_v6_src" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_saddr("fd00::/8"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip6_saddr(addr) string
```

#### Arguments

- `addr` (string) IPv6 address or CIDR (e.g., `2001:db8::1` or `fd00::/8`).

### `match_ip6_daddr`

Match the IPv6 destination address. Supports both single addresses and CIDR notation.

#### Example Usage

```terraform
resource "nftables_rule" "match_v6_dst" {
  family = "ip6"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_daddr("2001:db8::/32"),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip6_daddr(addr) string
```

#### Arguments

- `addr` (string) IPv6 address or CIDR.

### `match_ip6_hoplimit`

Match the IPv6 hop limit field.

#### Example Usage

```terraform
resource "nftables_rule" "match_hoplimit" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_hoplimit(1),
    provider::nftables::drop(),
  )
}
```

#### Signature

```text
match_ip6_hoplimit(hoplimit) string
```

#### Arguments

- `hoplimit` (number) Hop limit value (0-255).

### `match_ip6_nexthdr`

Match the IPv6 next header protocol field.

#### Example Usage

```terraform
resource "nftables_rule" "match_v6_nexthdr" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ip6_nexthdr("tcp"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ip6_nexthdr(proto) string
```

#### Arguments

- `proto` (string) Protocol name: `tcp`, `udp`, `icmpv6`, `sctp`, etc.

---

## Transport Matchers

Functions for matching TCP, UDP, SCTP, and DCCP transport layer fields.

### `match_tcp_dport`

Match the TCP destination port.

#### Example Usage

```terraform
resource "nftables_rule" "allow_https" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_tcp_dport(port) string
```

#### Arguments

- `port` (number) TCP destination port number (0-65535).

### `match_tcp_sport`

Match the TCP source port.

#### Example Usage

```terraform
resource "nftables_rule" "match_tcp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_sport(1024),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_tcp_sport(port) string
```

#### Arguments

- `port` (number) TCP source port number (0-65535).

### `match_tcp_flags`

Match TCP flags. Multiple flags are separated by a pipe character.

#### Example Usage

```terraform
resource "nftables_rule" "syn_flood" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_flags("syn"),
    provider::nftables::limit(25, "second"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_tcp_flags(flags) string
```

#### Arguments

- `flags` (string) Pipe-separated TCP flags: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ecn`, `cwr`. Example: `"syn|ack"`.

### `match_udp_dport`

Match the UDP destination port.

#### Example Usage

```terraform
resource "nftables_rule" "allow_dns" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_dport(53),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_udp_dport(port) string
```

#### Arguments

- `port` (number) UDP destination port number (0-65535).

### `match_udp_sport`

Match the UDP source port.

#### Example Usage

```terraform
resource "nftables_rule" "match_udp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_udp_sport(123),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_udp_sport(port) string
```

#### Arguments

- `port` (number) UDP source port number (0-65535).

### `match_sctp_dport`

Match the SCTP destination port.

#### Example Usage

```terraform
resource "nftables_rule" "allow_sctp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_sctp_dport(3868),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_sctp_dport(port) string
```

#### Arguments

- `port` (number) SCTP destination port number (0-65535).

### `match_sctp_sport`

Match the SCTP source port.

#### Example Usage

```terraform
resource "nftables_rule" "match_sctp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_sctp_sport(3868),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_sctp_sport(port) string
```

#### Arguments

- `port` (number) SCTP source port number (0-65535).

### `match_dccp_dport`

Match the DCCP destination port.

#### Example Usage

```terraform
resource "nftables_rule" "allow_dccp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_dccp_dport(5004),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_dccp_dport(port) string
```

#### Arguments

- `port` (number) DCCP destination port number (0-65535).

### `match_dccp_sport`

Match the DCCP source port.

#### Example Usage

```terraform
resource "nftables_rule" "match_dccp_src" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_dccp_sport(5004),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_dccp_sport(port) string
```

#### Arguments

- `port` (number) DCCP source port number (0-65535).

---

## ICMP Matchers

Functions for matching ICMP and ICMPv6 message types.

### `match_icmp_type`

Match the ICMP message type (IPv4).

#### Example Usage

```terraform
resource "nftables_rule" "allow_ping" {
  family = "ip"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit(5, "second"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_icmp_type(type_name) string
```

#### Arguments

- `type_name` (string) ICMP type name: `echo-request`, `echo-reply`, `destination-unreachable`, `time-exceeded`, `parameter-problem`, `redirect`, etc.

### `match_icmpv6_type`

Match the ICMPv6 message type.

#### Example Usage

```terraform
resource "nftables_rule" "allow_ndp" {
  family = "ip6"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_icmpv6_type("nd-neighbor-solicit"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_icmpv6_type(type_name) string
```

#### Arguments

- `type_name` (string) ICMPv6 type name: `echo-request`, `echo-reply`, `nd-neighbor-solicit`, `nd-neighbor-advert`, `nd-router-solicit`, `nd-router-advert`, `mld-listener-query`, etc.

---

## Meta Matchers

Functions for matching packet metadata (interfaces, marks, protocol info, socket owner).

### `match_iifname`

Match the input (incoming) network interface name.

#### Example Usage

```terraform
resource "nftables_rule" "allow_loopback" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_iifname(name) string
```

#### Arguments

- `name` (string) Interface name (e.g., `lo`, `eth0`, `wlan0`, `br0`).

### `match_oifname`

Match the output (outgoing) network interface name.

#### Example Usage

```terraform
resource "nftables_rule" "forward_to_lan" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_oifname("eth1"),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_oifname(name) string
```

#### Arguments

- `name` (string) Interface name.

### `match_mark`

Match the packet mark (nfmark/fwmark).

#### Example Usage

```terraform
resource "nftables_rule" "match_marked" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_mark(100),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_mark(mark) string
```

#### Arguments

- `mark` (number) Mark value to match.

### `match_nfproto`

Match the nfproto (network-layer protocol family). Useful in `inet` family tables to distinguish IPv4 and IPv6 traffic.

#### Example Usage

```terraform
resource "nftables_rule" "ipv4_only" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_nfproto("ipv4"),
    provider::nftables::match_tcp_dport(22),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_nfproto(proto) string
```

#### Arguments

- `proto` (string) Protocol family. Valid values: `ipv4` (or `ip`), `ipv6` (or `ip6`).

### `match_l4proto`

Match the layer 4 protocol by name.

#### Example Usage

```terraform
resource "nftables_rule" "match_tcp" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_l4proto("tcp"),
    provider::nftables::jump("tcp_chain"),
  )
}
```

#### Signature

```text
match_l4proto(proto) string
```

#### Arguments

- `proto` (string) Protocol name: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `dccp`, etc.

### `match_pkttype`

Match the packet type (unicast, broadcast, multicast).

#### Example Usage

```terraform
resource "nftables_rule" "drop_broadcast" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_pkttype("broadcast"),
    provider::nftables::drop(),
  )
}
```

#### Signature

```text
match_pkttype(pkttype) string
```

#### Arguments

- `pkttype` (string) Packet type. Valid values: `host`, `broadcast`, `multicast`, `other`.

### `match_skuid`

Match the UID of the socket owner process. Only available in the output chain.

#### Example Usage

```terraform
resource "nftables_rule" "match_user" {
  family = "inet"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_skuid(1000),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_skuid(uid) string
```

#### Arguments

- `uid` (number) UID of the socket owner.

### `match_skgid`

Match the GID of the socket owner process. Only available in the output chain.

#### Example Usage

```terraform
resource "nftables_rule" "match_group" {
  family = "inet"
  table  = "filter"
  chain  = "output"
  expr = provider::nftables::combine(
    provider::nftables::match_skgid(1000),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_skgid(gid) string
```

#### Arguments

- `gid` (number) GID of the socket owner.

---

## CT (Connection Tracking) Matchers

Functions for matching conntrack (connection tracking) state and metadata.

### `match_ct_state`

Match the conntrack state of the connection. Accepts a list of state names.

#### Example Usage

```terraform
resource "nftables_rule" "allow_established" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["established", "related"]),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ct_state(states) string
```

#### Arguments

- `states` (list of string) List of conntrack states. Valid values: `new`, `established`, `related`, `invalid`, `untracked`.

### `match_ct_mark`

Match the conntrack mark on the connection.

#### Example Usage

```terraform
resource "nftables_rule" "match_ct_marked" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_mark(42),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ct_mark(mark) string
```

#### Arguments

- `mark` (number) Conntrack mark value to match.

### `match_ct_status`

Match the conntrack status bits. Accepts a list of status names.

#### Example Usage

```terraform
resource "nftables_rule" "match_ct_assured" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_status(["assured", "confirmed"]),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ct_status(statuses) string
```

#### Arguments

- `statuses` (list of string) List of conntrack status bits. Valid values: `expected`, `seen-reply`, `assured`, `confirmed`, `snat`, `dnat`, `dying`.

### `match_ct_direction`

Match the conntrack direction of the packet within the connection.

#### Example Usage

```terraform
resource "nftables_rule" "match_original" {
  family = "inet"
  table  = "filter"
  chain  = "forward"
  expr = provider::nftables::combine(
    provider::nftables::match_ct_direction("original"),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}
```

#### Signature

```text
match_ct_direction(direction) string
```

#### Arguments

- `direction` (string) Connection direction. Valid values: `original`, `reply`.

---

## Complete Example

A full firewall configuration using provider functions:

```terraform
provider "nftables" {}

resource "nftables_table" "filter" {
  family = "inet"
  name   = "filter"
}

resource "nftables_chain" "input" {
  family   = nftables_table.filter.family
  table    = nftables_table.filter.name
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "drop"
}

# Accept established and related connections
resource "nftables_rule" "established" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["established", "related"]),
    provider::nftables::accept(),
  )
}

# Drop invalid connections
resource "nftables_rule" "drop_invalid" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_ct_state(["invalid"]),
    provider::nftables::counter(),
    provider::nftables::drop(),
  )
}

# Accept loopback
resource "nftables_rule" "loopback" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_iifname("lo"),
    provider::nftables::accept(),
  )
}

# Rate-limited ICMP
resource "nftables_rule" "ping" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_icmp_type("echo-request"),
    provider::nftables::limit(5, "second"),
    provider::nftables::accept(),
  )
}

# SSH with counter
resource "nftables_rule" "ssh" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(22),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}

# HTTPS
resource "nftables_rule" "https" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::match_tcp_dport(443),
    provider::nftables::counter(),
    provider::nftables::accept(),
  )
}

# Log and drop everything else
resource "nftables_rule" "log_drop" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine(
    provider::nftables::log("DROP: ", "info"),
    provider::nftables::counter(),
    provider::nftables::drop(),
  )
}
```
