#
#
#

import socket
from logging import getLogger
from os import listdir
from os.path import join

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
from dns import tsigkeyring
from dns.exception import DNSException
from dns.update import Update as DnsUpdate

from octodns.provider.base import BaseProvider
from octodns.record import Create, Record, Rr, Update
from octodns.source.base import BaseSource

__VERSION__ = '0.0.4'


class RfcPopulate:
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'CAA',
            'CNAME',
            'LOC',
            'MX',
            'NS',
            'PTR',
            'SPF',
            'SRV',
            'SSHFP',
            'TLSA',
            'TXT',
        )
    )

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)
        rrs = self.zone_records(zone)
        for record in Record.from_rrs(zone, rrs, lenient=lenient):
            zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records', len(zone.records) - before
        )

        # TODO: how do we do exists
        return True


class ZoneFileSourceException(Exception):
    pass


class ZoneFileSourceNotFound(ZoneFileSourceException):
    def __init__(self, path):
        super().__init__(f'Zone file not found at {path}')


class ZoneFileSourceLoadFailure(ZoneFileSourceException):
    def __init__(self, error):
        super().__init__(str(error))


class ZoneFileSource(RfcPopulate, BaseSource):
    def __init__(self, id, directory, file_extension='.', check_origin=True):
        self.log = getLogger(f'ZoneFileSource[{id}]')
        self.log.debug(
            '__init__: id=%s, directory=%s, file_extension=%s, '
            'check_origin=%s',
            id,
            directory,
            file_extension,
            check_origin,
        )
        super().__init__(id)
        self.directory = directory
        self.file_extension = file_extension
        self.check_origin = check_origin

        self._zone_records = {}

    def _load_zone_file(self, zone_name):
        zone_filename = f'{zone_name[:-1]}{self.file_extension}'
        zonefiles = listdir(self.directory)
        path = join(self.directory, zone_filename)
        if zone_filename in zonefiles:
            try:
                z = dns.zone.from_file(
                    path,
                    zone_name,
                    relativize=False,
                    check_origin=self.check_origin,
                )
            except DNSException as error:
                raise ZoneFileSourceLoadFailure(error)
        else:
            raise ZoneFileSourceNotFound(path)

        return z

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            z = self._load_zone_file(zone.name)

            records = []
            for name, ttl, rdata in z.iterate_rdatas():
                rdtype = dns.rdatatype.to_text(rdata.rdtype)
                if rdtype in self.SUPPORTS:
                    records.append(
                        Rr(name.to_text(), rdtype, ttl, rdata.to_text())
                    )

            self._zone_records[zone.name] = records

        return self._zone_records[zone.name]


class AxfrSourceException(Exception):
    pass


class AxfrSourceZoneTransferFailed(AxfrSourceException):
    def __init__(self, err):
        super().__init__(f'Unable to Perform Zone Transfer: {err}')


class AxfrPopulate(RfcPopulate):
    def __init__(
        self,
        id,
        host,
        port=53,
        ipv6=False,
        timeout=15,
        key_name=None,
        key_secret=None,
        key_algorithm=None,
    ):
        self.log = getLogger(f'{self.__class__.__name__}[{id}]')
        self.log.debug(
            '__init__: id=%s, host=%s, port=%d, ipv6=%s, timeout=%d, key_name=%s, key_secret=%s, key_algorithm=%s',
            id,
            host,
            port,
            ipv6,
            timeout,
            key_name,
            key_secret is not None,
            key_algorithm is not None,
        )
        super().__init__(id)
        self.host = self._host(host, ipv6)
        self.port = int(port)
        self.ipv6 = ipv6
        self.timeout = float(timeout)
        self.key_name = key_name
        self.key_secret = key_secret
        self.key_algorithm = key_algorithm

    def _host(self, host, ipv6):
        h = host
        try:
            # Determine if IPv4/IPv6 address
            dns.inet.af_for_address(host)
        except ValueError:
            address_family = socket.AF_INET
            if ipv6:
                address_family = socket.AF_INET6

            try:
                h = socket.getaddrinfo(host, None, address_family)[0][4][0]
            except OSError as err:
                raise AxfrSourceZoneTransferFailed(err)

        return h

    def _auth_params(self):
        params = {}
        if self.key_name is not None:
            params['keyring'] = tsigkeyring.from_text(
                {self.key_name: self.key_secret}
            )
        if self.key_algorithm is not None:
            params['keyalgorithm'] = self.key_algorithm
        return params

    def zone_records(self, zone):
        auth_params = self._auth_params()
        try:
            z = dns.zone.from_xfr(
                dns.query.xfr(
                    self.host,
                    zone.name,
                    port=self.port,
                    timeout=self.timeout,
                    lifetime=self.timeout,
                    relativize=False,
                    **auth_params,
                ),
                relativize=False,
            )
        except DNSException as err:
            raise AxfrSourceZoneTransferFailed(err) from None

        records = []

        for name, ttl, rdata in z.iterate_rdatas():
            rdtype = dns.rdatatype.to_text(rdata.rdtype)
            if rdtype in self.SUPPORTS:
                records.append(Rr(name.to_text(), rdtype, ttl, rdata.to_text()))

        return records


class AxfrSource(AxfrPopulate, BaseSource):
    pass


class Rfc2136ProviderException(Exception):
    pass


class Rfc2136ProviderUpdateFailed(Rfc2136ProviderException):
    def __init__(self, err):
        super().__init__(f'Unable to perform update: {err}')


class Rfc2136Provider(AxfrPopulate, BaseProvider):
    '''
    RFC-2136 7.6: States it's not possible to create zones, so we'll assume they
    exist and let things blow up during apply if there are problems It's a
    little ugly to inherit from two things that both ultimiately inherit from
    BaseSource, but it works. Some refactor
    '''

    SUPPORTS_ROOT_NS = True

    def _apply(self, plan):
        desired = plan.desired
        auth_params = self._auth_params()
        update = DnsUpdate(desired.name, **auth_params)

        for change in plan.changes:
            record = change.record

            name, ttl, _type, rdatas = record.rrs
            if isinstance(change, Create):
                update.add(name, ttl, _type, *rdatas)
            elif isinstance(change, Update):
                update.replace(name, ttl, _type, *rdatas)
            else:  # isinstance(change, Delete):
                update.delete(name, _type, *rdatas)

        r: dns.message.Message = dns.query.tcp(
            update, self.host, port=self.port, timeout=self.timeout
        )
        if r.rcode() != dns.rcode.NOERROR:
            raise Rfc2136ProviderUpdateFailed(dns.rcode.to_text(r.rcode()))

        self.log.debug(
            '_apply: zone=%s, num_records=%d', name, len(plan.changes)
        )

        return True


BindProvider = Rfc2136Provider
