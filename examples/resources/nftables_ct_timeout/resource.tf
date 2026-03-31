# Custom TCP timeout policy with aggressive timeouts
resource "nftables_ct_timeout" "tcp_aggressive" {
  family   = "inet"
  table    = "filter"
  name     = "tcp_aggressive"
  protocol = "tcp"
  l3proto  = "ip"

  policy = {
    established = 300
    close_wait  = 10
    close       = 5
    time_wait   = 30
    syn_sent    = 10
    syn_recv    = 10
    last_ack    = 10
  }
}

# Custom UDP timeout policy
resource "nftables_ct_timeout" "udp_short" {
  family   = "inet"
  table    = "filter"
  name     = "udp_short"
  protocol = "udp"
  l3proto  = "ip"

  policy = {
    unreplied = 15
    replied   = 60
  }
}
