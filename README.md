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
      file_extension: .zone
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
      # The port that the nameserver is listening on. Optional. Default: 53
      port: 53
      # Use IPv6 to perform operations. Optional. Default: False
      ipv6: False
      # The number of seconds to wait until timing out. Optional. Default: 15
      timeout: 15
      # optional, default: non-authed
      key_name: env/AXFR_KEY_NAME
      # optional, default: non-authed
      key_secret: env/AXFR_KEY_SECRET
      # optional, see https://github.com/rthalley/dnspython/blob/master/dns/tsig.py#L78
      # for available algorithms
      key_algorithm: hmac-sha1
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
      class: octodns_bind.Rfc2136Provider
      # The address of nameserver to perform zone transfer against
      host: ns1.example.com
      # The port that the nameserver is listening on. Optional. Default: 53
      port: 53
      # Use IPv6 to perform operations. Optional. Default: False
      ipv6: False
      # The number of seconds to wait until timing out. Optional. Default: 15
      timeout: 15
      # optional, default: non-authed
      key_name: env/AXFR_KEY_NAME
      # optional, default: non-authed
      key_secret: env/AXFR_KEY_SECRET
      # optional, see https://github.com/rthalley/dnspython/blob/master/dns/tsig.py#L78
      # for available algorithms
      key_algorithm: hmac-sha1
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

#### ZoneFileProvider

A provider that reads and writes [Bind9](https://www.isc.org/bind/) compliant zone files

```
providers:
  zonefile:
    class: octodns_bind.ZoneFileProvider

    # The location of zone files. Records are defined in a
    # file named for the zone in this directory, e.g.
    # something.com., including the trailing ., see `file_extension` below
    # (required)
    directory: ./config

    # The extension to use when working with zone files. It is appended onto
    # the zone name to determine the file when reading or writing
    # records. Some operating systems do not allow filenames ending with a .
    # and this value may need to be changed when working on them, e.g. to
    # .zone. The leading . should be included.
    # (default: .)
    file_extension: .

    # Wether the provider should check for the existence a root NS record
    # when loading a zone
    # (default: true)
    check_origin: true

    # The email username or full address to be used when creating zonefiles.
    # If this is just a username, no @[domain.com.], the current zone name
    # will be appended to this value. If the value is a complete email
    # address it will be used as-is. Note that the actual email address with
    # a @ should be used and not the zone file format with the value
    # replaced with a `.`.
    # (default: webmaster)
    hostmaster_email: webmaster

    # The details of the SOA record can be customized when creating
    # zonefiles with the following options.
    default_ttl: 3600
    refresh: 3600
    retry: 600
    expire: 604800
    nxdomain: 3600
```

### Support Information

#### Records

A, AAAA, CAA, CNAME, LOC, MX, NS, PTR, SPF, SRV, SSHFP, TLSA, TXT

#### Dynamic

This module does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.

#### Local Server

A local server is included in the repo via [docker-compose.yml](/docker-compose.yml). This will set up a Bind9 server with AXFR transfers and RFC 2136 updates enabled for use in development on IPv4 and IPv6. Configuration for the server can be found in [docker/etc/bind/named.conf](docker/etc/bind/named.conf), including the TSIG secret which can be used to perform authenticated operations. Zonefiles can be found in [docker/var/lib/bind](docker/var/lib/bind). All logs are written to STDOUT and can be viewed by running `docker-compose logs -f`

An example octodns configuration to interact with the local server is below:

```yaml
providers:
  rfc2136:
    class: octodns_bind.Rfc2136Provider
    host: localhost
    key_name: 'octodns.exxampled.com.'
    key_secret: 'vZew5TtZLTZKTCl00xliGt+1zzsuLWQWFz48bRbPnZU='
    key_algorithm: 'hmac-sha256'

zones:
  exxampled.com.:
    sources:
      - config
    targets:
      - rfc2136
```
