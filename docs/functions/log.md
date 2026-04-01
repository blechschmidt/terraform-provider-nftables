---
page_title: "log function - nftables"
subcategory: ""
description: |-
  Log matching packets
---

# function: log

Log matching packets

## Signature

```text
log(prefix string, level string) string
```

## Arguments

1. `prefix` (String) Log prefix string
2. `level` (String) Log level: emerg, alert, crit, err, warn, notice, info, debug
