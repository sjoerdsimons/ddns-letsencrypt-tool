# DDNS ❤️  letsencrypt

A simple rust tool that combines an RFC2136 dynamic dns updates client with an
acme client supporting the dns01 challenge protocol.

For usage see the example [config](data/config.yml) and
[systemd service](data/ddns-letsencrypt-tool.service)


Tested with [knot-dns](https://www.knot-dns.cz/) as the DNS server and
[letsencrypt](https://letsencrypt.org/) as the certificate service
