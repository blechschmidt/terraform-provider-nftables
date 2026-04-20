# terraform-provider-nftables

A Terraform provider for managing Linux [nftables](https://wiki.nftables.org/) firewall rules declaratively. It talks directly to the kernel over netlink via [google/nftables](https://github.com/google/nftables) — there is no dependency on the `nft` CLI.

## Features

- All 14 nftables object types: tables, chains, rules, sets, maps, flowtables, counters, quotas, limits, and the full conntrack/secmark/synproxy family.
- All 6 address families: `ip`, `ip6`, `inet`, `arp`, `bridge`, `netdev`.
- Three ways to author rules:
  - `expression` — familiar `nft` syntax (`tcp dport 22 counter accept`).
  - `expr` — JSON-encoded netlink VM statement lists for full kernel-level control.
  - 64 provider-defined functions (`provider::nftables::*`) for type-safe rule composition.
- Optional network namespace support via the `namespace` provider argument.

## Installation

```terraform
terraform {
  required_providers {
    nftables = {
      source = "blechschmidt/nftables"
    }
  }
}

provider "nftables" {
  # namespace = "my_netns"  # optional
}
```

## Quick example

```terraform
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

resource "nftables_rule" "established" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "ct state established,related accept"
}

resource "nftables_rule" "ssh" {
  family     = nftables_table.filter.family
  table      = nftables_table.filter.name
  chain      = nftables_chain.input.name
  expression = "tcp dport 22 counter accept"
}
```

### Provider functions

Composable, type-safe rule building. `combine()` merges expression lists into a single rule body:

```terraform
resource "nftables_rule" "https" {
  family = nftables_table.filter.family
  table  = nftables_table.filter.name
  chain  = nftables_chain.input.name
  expr = provider::nftables::combine([
    provider::nftables::match_iifname("eth0"),
    provider::nftables::match_tcp_dport(443),
    provider::nftables::match_ct_state(["new"]),
    provider::nftables::counter(),
    provider::nftables::accept(),
  ])
}
```

## Documentation

Full documentation lives in [`docs/`](./docs) and on the Terraform Registry:

- [Provider overview](./docs/index.md)
- [Resources](./docs/resources)
- [Provider functions](./docs/functions)
- [Examples](./examples)

## Requirements

- Linux kernel with nftables support.
- `CAP_NET_ADMIN` on the process running Terraform (typically root, or a capability-granted user).
- Terraform >= 1.8 (required for provider-defined functions).

## Development

```sh
make build      # build the provider binary
make install    # install into ~/.terraform.d/plugins for local use
make test       # unit tests
make testacc    # acceptance tests (require root and a test netns)
make lint       # golangci-lint
make coverage   # generate coverage.html
```

The acceptance test suite creates and tears down rules inside a dedicated network namespace — it must be run as root.

## License

See repository for license details.
