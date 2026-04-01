---
page_title: "match_tcp_flags function - nftables"
subcategory: ""
description: |-
  Match TCP flags
---

# function: match_tcp_flags

Match TCP flags

## Example Usage

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

## Signature

```text
match_tcp_flags(flags string) string
```

## Arguments

1. `flags` (String) Pipe-separated TCP flags: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ecn`, `cwr`. Example: `"syn|ack"`.
