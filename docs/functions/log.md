---
page_title: "log function - nftables"
subcategory: ""
description: |-
  Log matching packets
---

# function: log

Log matching packets

## Example Usage

```terraform
resource "nftables_rule" "log_dropped" {
  family = "inet"
  table  = "filter"
  chain  = "input"
  expr = provider::nftables::combine(
    provider::nftables::limit(5, "minute"),
    provider::nftables::log("DROPPED", "warn"),
    provider::nftables::drop(),
  )
}
```

## Signature

```text
log(prefix string, level string) string
```

## Arguments

1. `prefix` (String) Log prefix string.
2. `level` (String) Log level: `emerg`, `alert`, `crit`, `err`, `warn`, `notice`, `info`, `debug`.
