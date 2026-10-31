# Import an existing registered zone before managing registry settings.
resource "gigahost_dns_zone" "registered" {
  zone_name      = "example.no"
  nameservers    = ["ns1.gigahost.no", "ns2.gigahost.no", "ns3.gigahost.no"]
  dnssec_enabled = true
}

import {
  to = gigahost_dns_zone.registered
  id = "123"
}
