## v0.0.5 - 2023-09-12 - Write that which we can read

- ZoneFileProvider, full support writing zone files out to disk
- ZoneFileSource.list_zones added to support dynamic zone config

## v0.0.4 - 2023-05-23 - First Stop /etc/hosts

- Use socket.gethostaddr instead of dns.resolver.resolve to look up host
- Add timeout for zone transfers and updates

## v0.0.3 - 2023-05-14 - TSLA, Error, and DNS host

- Host can be a DNS name or an IP address
- ZoneFileSource will error if file is not found
- Support for TLSA records

## v0.0.2 - 2023-04-05 - Ports and Crypto

- Add port parameter to AXFR source and RFC2136 provider.
- Add key_algorithm parameter for TSIG
- Error when RFC2136 provider is unable to perform an update

## v0.0.1 - 2022-10-10 - In the beginning

* Initial extraction of octodns.axfr.* from octoDNS core
* Support for RFC 2631 record updates, making this capable of fully managing DNS
  servers that support it (and AXFR.)
