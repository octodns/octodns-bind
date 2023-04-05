## v0.0.2 - 2023-04-05 - Ports and Crypto

- Add port parameter to AXFR source and RFC2136 provider.
- Add key_algorithm parameter for TSIG
- Error when RFC2136 provider is unable to perform an update

## v0.0.1 - 2022-10-10 - In the beginning

* Initial extraction of octodns.axfr.* from octoDNS core
* Support for RFC 2631 record updates, making this capable of fully managing DNS
  servers that support it (and AXFR.)
