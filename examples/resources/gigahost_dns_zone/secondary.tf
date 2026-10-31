# Secondary zones use the SLAVE zone type and specify their primary servers.
resource "gigahost_dns_zone" "secondary" {
  zone_name = "example.net"
  zone_type = "SLAVE"
  masters   = ["192.0.2.1", "192.0.2.2"]
}
