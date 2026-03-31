# FTP connection tracking helper
resource "nftables_ct_helper" "ftp" {
  family   = "inet"
  table    = "filter"
  name     = "ftp"
  helper   = "ftp"
  protocol = "tcp"
  l3proto  = "ip"
}

# SIP connection tracking helper
resource "nftables_ct_helper" "sip" {
  family   = "inet"
  table    = "filter"
  name     = "sip"
  helper   = "sip"
  protocol = "udp"
  l3proto  = "ip"
}

# TFTP connection tracking helper
resource "nftables_ct_helper" "tftp" {
  family   = "inet"
  table    = "filter"
  name     = "tftp"
  helper   = "tftp"
  protocol = "udp"
  l3proto  = "ip"
}
