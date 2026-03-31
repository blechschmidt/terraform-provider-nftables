# Verdict map for per-interface policy
resource "nftables_map" "iface_policy" {
  family    = "inet"
  table     = "filter"
  name      = "iface_policy"
  key_type  = "ifname"
  data_type = "verdict"

  elements = [
    "\"eth0\" : accept",
    "\"eth1\" : drop",
    "\"eth2\" : jump tcp_checks",
  ]
}

# NAT map for port-based DNAT
resource "nftables_map" "port_forward" {
  family    = "ip"
  table     = "nat"
  name      = "port_forward"
  key_type  = "inet_service"
  data_type = "ipv4_addr . inet_service"

  elements = [
    "80 : 192.168.1.10 . 80",
    "443 : 192.168.1.10 . 443",
    "8080 : 192.168.1.20 . 8080",
  ]
}

# Map source IPs to marks
resource "nftables_map" "ip_to_mark" {
  family    = "inet"
  table     = "filter"
  name      = "ip_to_mark"
  key_type  = "ipv4_addr"
  data_type = "mark"
  flags     = ["interval"]

  elements = [
    "192.168.1.0/24 : 0x1",
    "192.168.2.0/24 : 0x2",
    "10.0.0.0/8 : 0x3",
  ]

  comment = "Assign packet marks based on source network"
}
