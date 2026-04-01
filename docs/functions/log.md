---
page_title: "log function - nftables"
subcategory: ""
description: |-
  Log matching packets.
---

# function: log

Returns an expression that logs matching packets to the kernel log with a prefix and severity level.

## Example Usage

```terraform
# Log and drop
expr = provider::nftables::combine(
  provider::nftables::limit(5, "minute"),
  provider::nftables::log("DROPPED", "warn"),
  provider::nftables::drop(),
)
```

## Signature

```text
log(prefix, level) string
```

## Arguments

- `prefix` (String) Log message prefix string.
- `level` (String) Syslog level: `"emerg"`, `"alert"`, `"crit"`, `"err"`, `"warn"`, `"notice"`, `"info"`, `"debug"`.
