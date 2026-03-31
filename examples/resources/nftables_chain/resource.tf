# Base chain for filtering incoming traffic
resource "nftables_chain" "input" {
  family   = "inet"
  table    = "filter"
  name     = "input"
  type     = "filter"
  hook     = "input"
  priority = 0
  policy   = "drop"
}

# Base chain for forwarding traffic
resource "nftables_chain" "forward" {
  family   = "inet"
  table    = "filter"
  name     = "forward"
  type     = "filter"
  hook     = "forward"
  priority = 0
  policy   = "drop"
}

# Base chain for output traffic
resource "nftables_chain" "output" {
  family   = "inet"
  table    = "filter"
  name     = "output"
  type     = "filter"
  hook     = "output"
  priority = 0
  policy   = "accept"
}

# NAT postrouting chain
resource "nftables_chain" "postrouting" {
  family   = "ip"
  table    = "nat"
  name     = "postrouting"
  type     = "nat"
  hook     = "postrouting"
  priority = 100
}

# Regular (non-base) chain used as a jump target
resource "nftables_chain" "tcp_checks" {
  family = "inet"
  table  = "filter"
  name   = "tcp_checks"
}

# Netdev ingress chain bound to a specific device
resource "nftables_chain" "ingress" {
  family   = "netdev"
  table    = "filter"
  name     = "ingress"
  type     = "filter"
  hook     = "ingress"
  priority = 0
  device   = "eth0"
}
