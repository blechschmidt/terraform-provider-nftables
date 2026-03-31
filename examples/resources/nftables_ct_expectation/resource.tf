# Expectation for FTP data connections
resource "nftables_ct_expectation" "ftp_data" {
  family   = "inet"
  table    = "filter"
  name     = "ftp_data"
  protocol = "tcp"
  l3proto  = "ip"
  dport    = 20
  timeout  = 300
  size     = 8
}

# Expectation for SIP RTP streams
resource "nftables_ct_expectation" "sip_rtp" {
  family   = "inet"
  table    = "filter"
  name     = "sip_rtp"
  protocol = "udp"
  l3proto  = "ip"
  dport    = 5060
  timeout  = 180
  size     = 16
}
