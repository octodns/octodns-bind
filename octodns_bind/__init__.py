#
#
#

from dns.exception import DNSException
import dns.name
import dns.query
import dns.zone
import dns.rdatatype

from logging import getLogger
from os import listdir
from os.path import join

from octodns.provider.base import BaseProvider
from octodns.record import Record, Rr
from octodns.source.base import BaseSource

__VERSION__ = '0.0.1'


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


class ZoneFileSourceException(Exception):
    pass


class ZoneFileSourceNotFound(ZoneFileSourceException):
    def __init__(self):
        super().__init__('Zone file not found')


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
        if zone_filename in zonefiles:
            try:
                z = dns.zone.from_file(
                    join(self.directory, zone_filename),
                    zone_name,
                    relativize=False,
                    check_origin=self.check_origin,
                )
            except DNSException as error:
                raise ZoneFileSourceLoadFailure(error)
        else:
            raise ZoneFileSourceNotFound()

        return z

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                z = self._load_zone_file(zone.name)
            except ZoneFileSourceNotFound:
                return []

            records = []
            for (name, ttl, rdata) in z.iterate_rdatas():
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
    def __init__(self):
        super().__init__('Unable to Perform Zone Transfer')


class AxfrPopulate(RfcPopulate):
    def zone_records(self, zone):
        try:
            z = dns.zone.from_xfr(
                dns.query.xfr(self.host, zone.name, relativize=False),
                relativize=False,
            )
        except DNSException:
            raise AxfrSourceZoneTransferFailed()

        records = []

        for (name, ttl, rdata) in z.iterate_rdatas():
            rdtype = dns.rdatatype.to_text(rdata.rdtype)
            if rdtype in self.SUPPORTS:
                records.append(Rr(name.to_text(), rdtype, ttl, rdata.to_text()))

        return records


class AxfrSource(AxfrPopulate, BaseSource):
    def __init__(self, id, host, key_name=None, key_secret=None):
        self.log = getLogger(f'AxfrSource[{id}]')
        self.log.debug(
            '__init__: id=%s, host=%s, key_name=%s, key_secret=%s',
            id,
            host,
            key_name,
            key_secret is not None,
        )
        super().__init__(id)
        self.host = host
        self.key_name = key_name
        self.key_secret = key_secret


class Rfc2136Provider(AxfrPopulate, BaseProvider):
    pass


BindProvider = Rfc2136Provider
