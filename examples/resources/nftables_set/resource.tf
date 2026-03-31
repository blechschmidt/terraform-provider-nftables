# Simple IP address set for a blocklist
resource "nftables_set" "blocklist" {
  family = "inet"
  table  = "filter"
  name   = "blocklist"
  type   = "ipv4_addr"

  elements = [
    "192.168.1.100",
    "10.0.0.50",
  ]
}

# Interval set for network ranges with auto-merge
resource "nftables_set" "trusted_nets" {
  family     = "inet"
  table      = "filter"
  name       = "trusted_nets"
  type       = "ipv4_addr"
  flags      = ["interval"]
  auto_merge = true

  elements = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
  ]
}

# Port set
resource "nftables_set" "allowed_ports" {
  family = "inet"
  table  = "filter"
  name   = "allowed_ports"
  type   = "inet_service"

  elements = [
    "22",
    "80",
    "443",
    "8080",
  ]
}

# Set with timeout for dynamic entries
resource "nftables_set" "rate_limited" {
  family  = "inet"
  table   = "filter"
  name    = "rate_limited"
  type    = "ipv4_addr"
  flags   = ["timeout"]
  timeout = 300
}

# Set with per-element counters
resource "nftables_set" "monitored_hosts" {
  family  = "inet"
  table   = "filter"
  name    = "monitored_hosts"
  type    = "ipv4_addr"
  counter = true
  comment = "Hosts with per-element packet counters"

  elements = [
    "10.0.0.1",
    "10.0.0.2",
  ]
}
