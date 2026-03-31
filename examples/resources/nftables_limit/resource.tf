# Limit to 25 packets per minute (e.g., for SSH)
resource "nftables_limit" "ssh_rate" {
  family = "inet"
  table  = "filter"
  name   = "ssh_rate"
  rate   = 25
  unit   = "minute"
  type   = "packets"
}

# Limit to 5 packets per second with a burst of 10
resource "nftables_limit" "icmp_rate" {
  family = "inet"
  table  = "filter"
  name   = "icmp_rate"
  rate   = 5
  unit   = "second"
  burst  = 10
  type   = "packets"
}

# Byte-based limit for bandwidth throttling (1 MB/s)
resource "nftables_limit" "bandwidth" {
  family = "inet"
  table  = "filter"
  name   = "bandwidth"
  rate   = 1048576
  unit   = "second"
  type   = "bytes"
  burst  = 2097152
}

# Inverse limit - matches when rate is exceeded (for dropping)
resource "nftables_limit" "flood_detect" {
  family = "inet"
  table  = "filter"
  name   = "flood_detect"
  rate   = 100
  unit   = "second"
  type   = "packets"
  over   = true
}
