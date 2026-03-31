# Quota limiting a host to 1 GB of traffic
resource "nftables_quota" "daily_limit" {
  family = "inet"
  table  = "filter"
  name   = "daily_limit"
  bytes  = 1073741824
}

# Quota that matches after exceeding 500 MB (for logging/dropping)
resource "nftables_quota" "over_limit" {
  family = "inet"
  table  = "filter"
  name   = "over_limit"
  bytes  = 536870912
  over   = true
}

# Quota with pre-set consumed bytes
resource "nftables_quota" "restored" {
  family   = "inet"
  table    = "filter"
  name     = "restored"
  bytes    = 10737418240
  consumed = 5368709120
}
