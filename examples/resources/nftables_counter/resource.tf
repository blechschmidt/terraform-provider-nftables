# Counter for tracking HTTPS traffic
resource "nftables_counter" "https_traffic" {
  family = "inet"
  table  = "filter"
  name   = "https_traffic"
}

# Counter with initial values
resource "nftables_counter" "ssh_traffic" {
  family  = "inet"
  table   = "filter"
  name    = "ssh_traffic"
  packets = 0
  bytes   = 0
}

# Counter for dropped packets
resource "nftables_counter" "dropped" {
  family = "inet"
  table  = "filter"
  name   = "dropped"
}
