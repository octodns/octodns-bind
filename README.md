## RFC compliant (Bind9) provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Bind](https://www.isc.org/bind/) and other standards compliant servers. It includes support for sourcing records via AXFR, reading zone files, and fully managing records with [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136).

### Installation

#### Command line

```
pip install octodns-bind
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.20
octodns-bind==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-bind.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_bind
```

### Configuration

#### ZoneFileSource

A source that reads DNS records from zone files in a local directory.

```yaml
providers:
  zonefile:
      class: octodns_bind.ZoneFileSource
      # The directory holding the zone files
      # Filenames should match zone name (eg. example.com.)
      # with optional extension specified with file_extension
      directory: ./zonefiles
      # File extension on zone files
      # Appended to zone name to locate file
      # (optional, default None)
      file_extension: zone
      # Should sanity checks of the origin node be done
      # (optional, default true)
      check_origin: false
```

#### AxfrSource

A source that support the AXFR protocol

```yaml
providers:
  axfr:
      class: octodns_bind.AxfrSource
      # The address of nameserver to perform zone transfer against
      host: ns1.example.com
      # optional, default: non-authed
      key_name: env/AXFR_KEY_NAME
      # optional, default: non-authed
      key_secret: env/AXFR_KEY_SECRET
```

See below for example Bind9 server configuration. Any server that supports RFC
compliant AXFR should work here. If you have a need for support of other auth
mechinism please open an issue.

#### Rfc2136Provider/BindProvider

A provider that combines AXFR and RFC 2136 to enable a full featured octoDNS
provider for the [Bind9 server](https://www.isc.org/bind/)

Both allow transfer 
  allow-transfer { key octodns.exxampled.com.; };
  allow-update { key octodns.exxampled.com.; };

```yaml
providers:
  rfc2136:
      # also available as octodns_bind.BindProvider
      class: octodns_bind.Rfc2136
      # The address of nameserver to perform zone transfer against
      host: ns1.example.com
      # optional, default: non-authed
      key_name: env/AXFR_KEY_NAME
      # optional, default: non-authed
      key_secret: env/AXFR_KEY_SECRET
```

Example Bind9 config to enable AXFR and RFC 2136

```
# generated with rndc-confgen
key octodns.exxampled.com. {
  algorithm hmac-sha256;
  secret "vZew5TtZLTZKTCl00xliGt+1zzsuLWQWFz48bRbPnZU=";
};

zone "exxampled.com." {
  type master;
  file "/var/lib/bind/db.exxampled.com";
  notify explicit;
  # this enables AXFR
  allow-transfer { key octodns.exxampled.com.; };
  # this allows RFC 2136
  allow-update { key octodns.exxampled.com.; };
};
```

Any server that supports RFC compliant AXFR and RFC 2136 should work here. If
you have a need for support of other auth mechinism please open an issue.

### Support Information

#### Records

A, AAAA, CAA, CNAME, LOC, MX, NS, PTR, SPF, SRV, SSHFP, TXT

#### Dynamic

This module does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

There is a [docker-compose.yml](/docker-compose.yml) file included in the repo that will set up a Bind9 server with AXFR transfers and RFC 2136 updates enabled for use in development. The secret for the server can be found in [docker/etc/bind/named.conf](docker/etc/bind/named.conf).
