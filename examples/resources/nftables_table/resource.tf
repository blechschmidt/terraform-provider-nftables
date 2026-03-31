resource "nftables_table" "filter" {
  family = "inet"
  name   = "filter"
}

resource "nftables_table" "nat" {
  family = "ip"
  name   = "nat"
}

# A dormant table (rules are not evaluated)
resource "nftables_table" "maintenance" {
  family  = "inet"
  name    = "maintenance"
  dormant = true
}
