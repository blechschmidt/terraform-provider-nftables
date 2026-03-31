# Synproxy for a web server
resource "nftables_synproxy" "web" {
  family    = "inet"
  table     = "filter"
  name      = "web"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}

# Synproxy without TCP options for legacy clients
resource "nftables_synproxy" "legacy" {
  family    = "inet"
  table     = "filter"
  name      = "legacy"
  mss       = 1460
  wscale    = 0
  timestamp = false
  sack_perm = false
}

# Synproxy for SSH protection
resource "nftables_synproxy" "ssh" {
  family    = "inet"
  table     = "filter"
  name      = "ssh"
  mss       = 1460
  wscale    = 7
  timestamp = true
  sack_perm = true
}
