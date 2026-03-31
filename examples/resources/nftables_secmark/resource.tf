# Secmark for HTTP server traffic
resource "nftables_secmark" "http" {
  family  = "inet"
  table   = "filter"
  name    = "http"
  context = "system_u:object_r:httpd_packet_t:s0"
}

# Secmark for SSH traffic
resource "nftables_secmark" "ssh" {
  family  = "inet"
  table   = "filter"
  name    = "ssh"
  context = "system_u:object_r:ssh_packet_t:s0"
}

# Secmark for DNS traffic
resource "nftables_secmark" "dns" {
  family  = "inet"
  table   = "filter"
  name    = "dns"
  context = "system_u:object_r:dns_packet_t:s0"
}
