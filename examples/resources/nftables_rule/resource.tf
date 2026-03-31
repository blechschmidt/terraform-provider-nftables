# Allow established and related connections
resource "nftables_rule" "allow_established" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state established,related accept"
}

# Drop invalid connections
resource "nftables_rule" "drop_invalid" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "ct state invalid drop"
}

# Allow loopback traffic
resource "nftables_rule" "allow_loopback" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta iifname \"lo\" accept"
}

# Allow ICMP echo requests (ping)
resource "nftables_rule" "allow_ping" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "icmp type echo-request accept"
}

# Allow SSH
resource "nftables_rule" "allow_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 accept"
}

# Allow HTTP and HTTPS
resource "nftables_rule" "allow_web" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport { 80, 443 } accept"
}

# Allow DNS
resource "nftables_rule" "allow_dns" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "udp dport 53 accept"
}

# Limit SSH connections to 3 per minute
resource "nftables_rule" "limit_ssh" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 22 ct state new limit rate 3/minute accept"
}

# Count and log dropped packets
resource "nftables_rule" "log_drops" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "counter log prefix \"nft-drop: \" drop"
}

# Source NAT (masquerade) for outgoing traffic
resource "nftables_rule" "masquerade" {
  family     = "ip"
  table      = "nat"
  chain      = "postrouting"
  expression = "oifname \"eth0\" masquerade"
}

# DNAT (port forwarding)
resource "nftables_rule" "dnat_web" {
  family     = "ip"
  table      = "nat"
  chain      = "prerouting"
  expression = "tcp dport 8080 dnat to 192.168.1.10:80"
}

# Reject with TCP reset
resource "nftables_rule" "reject_auth" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "tcp dport 113 reject with tcp reset"
}

# Jump to a sub-chain
resource "nftables_rule" "jump_tcp" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta l4proto tcp jump tcp_checks"
}

# Meta expression matching on interface
resource "nftables_rule" "allow_internal" {
  family     = "inet"
  table      = "filter"
  chain      = "input"
  expression = "meta iifname \"eth1\" accept"
}
