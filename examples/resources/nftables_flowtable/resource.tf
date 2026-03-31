# Flowtable for offloading forwarded traffic between LAN and WAN
resource "nftables_flowtable" "offload" {
  family   = "inet"
  table    = "filter"
  name     = "offload"
  hook     = "ingress"
  priority = 0
  devices  = ["eth0", "eth1"]
}

# Flowtable for a multi-interface router
resource "nftables_flowtable" "router_offload" {
  family   = "inet"
  table    = "filter"
  name     = "router_offload"
  hook     = "ingress"
  priority = -100
  devices  = ["eth0", "eth1", "eth2", "wlan0"]
}
