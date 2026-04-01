---
page_title: "match_tcp_flags function - nftables"
subcategory: ""
description: |-
  Match TCP flags
---

# function: match_tcp_flags

Match TCP flags

## Signature

```text
match_tcp_flags(flags string) string
```

## Arguments

1. `flags` (String) Pipe-separated flags: syn|ack|fin|rst|psh|urg|ecn|cwr
