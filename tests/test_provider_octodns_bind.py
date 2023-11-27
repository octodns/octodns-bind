#
#
#

import socket
from os.path import exists, join
from shutil import copyfile, rmtree
from tempfile import mkdtemp
from unittest import TestCase
from unittest.mock import patch

import dns.resolver
import dns.zone
from dns.exception import DNSException

from octodns.provider.plan import Plan
from octodns.record import Create, Record, Rr, ValidationError
from octodns.zone import Zone

from octodns_bind import (
    AxfrSource,
    AxfrSourceZoneTransferFailed,
    Rfc2136Provider,
    Rfc2136ProviderUpdateFailed,
    ZoneFileProvider,
    ZoneFileSource,
    ZoneFileSourceLoadFailure,
    ZoneFileSourceNotFound,
)


class TemporaryDirectory(object):
    def __init__(self, delete_on_exit=True):
        self.delete_on_exit = delete_on_exit

    def __enter__(self):
        self.dirname = mkdtemp()
        return self

    def __exit__(self, *args, **kwargs):
        if self.delete_on_exit:
            rmtree(self.dirname)
        else:
            raise Exception(self.dirname)


class TestAxfrSource(TestCase):
    source = AxfrSource('test', '127.0.0.1')

    forward_zonefile = dns.zone.from_file(
        './tests/zones/unit.tests.tst', 'unit.tests', relativize=False
    )

    reverse_zonefile = dns.zone.from_file(
        './tests/zones/2.0.192.in-addr.arpa.',
        '2.0.192.in-addr.arpa',
        relativize=False,
    )

    @patch('dns.zone.from_xfr')
    def test_populate_forward(self, from_xfr_mock):
        got = Zone('unit.tests.', [])

        from_xfr_mock.side_effect = [self.forward_zonefile, DNSException]

        self.source.populate(got)
        self.assertEqual(18, len(got.records))

        with self.assertRaises(AxfrSourceZoneTransferFailed) as ctx:
            zone = Zone('unit.tests.', [])
            self.source.populate(zone)
        self.assertEqual(
            'Unable to Perform Zone Transfer',
            str(ctx.exception).split(':', 1)[0],
        )

    @patch('dns.zone.from_xfr')
    def test_populate_reverse(self, from_xfr_mock):
        got = Zone('2.0.192.in-addr.arpa.', [])

        from_xfr_mock.side_effect = [self.reverse_zonefile]

        self.source.populate(got)
        self.assertEqual(4, len(got.records))


class TestZoneFileSource(TestCase):
    source = ZoneFileSource('test', './tests/zones', file_extension='.tst')

    def test_zonefile_not_found(self):
        with self.assertRaises(ZoneFileSourceNotFound) as ctx:
            source = ZoneFileSource('notfound', './tests/zones')
            notfound = Zone('not.found.', [])
            source.populate(notfound)

        self.assertEqual(
            'Zone file not found at ./tests/zones/not.found.',
            str(ctx.exception),
        )

    def test_zonefiles_with_extension(self):
        source = ZoneFileSource('test', './tests/zones', '.extension')
        # Load zonefiles with a specified file extension
        valid = Zone('ext.unit.tests.', [])
        source.populate(valid)
        self.assertEqual(1, len(valid.records))

    def test_zonefiles_without_extension(self):
        # Windows doesn't let files end with a `.` so we add a .tst to them in
        # the repo and then try and create the `.` version we need for the
        # default case (no extension.)
        copyfile('./tests/zones/unit.tests.tst', './tests/zones/unit.tests.')
        # Unfortunately copyfile silently works and create the file without
        # the `.` so we have to check to see if it did that
        if exists('./tests/zones/unit.tests'):
            # It did so we need to skip this test, that means windows won't
            # have full code coverage, but skipping the test is going out of
            # our way enough for a os-specific/oddball case.
            self.skipTest(
                'Unable to create unit.tests. (ending with .) so '
                'skipping default filename testing.'
            )

        source = ZoneFileSource('test', './tests/zones')
        # Load zonefiles without a specified file extension
        valid = Zone('unit.tests.', [])
        source.populate(valid)
        self.assertEqual(18, len(valid.records))

    def test_populate(self):
        # Valid zone file in directory
        valid = Zone('unit.tests.', [])
        self.source.populate(valid)
        self.assertEqual(18, len(valid.records))

        # 2nd populate does not read file again
        again = Zone('unit.tests.', [])
        self.source.populate(again)
        self.assertEqual(18, len(again.records))

        # bust the cache
        del self.source._zone_records[valid.name]

        # Zone file is not valid
        with self.assertRaises(ZoneFileSourceLoadFailure) as ctx:
            zone = Zone('invalid.zone.', [])
            self.source.populate(zone)
        self.assertEqual(
            'The DNS zone has no NS RRset at its origin.', str(ctx.exception)
        )

        # Records are not to RFC (lenient=False)
        with self.assertRaises(ValidationError) as ctx:
            zone = Zone('invalid.records.', [])
            self.source.populate(zone)
        # quotes were added to the record name 1.0.0rc1, this makes it work with
        # both version
        reason = str(ctx.exception).replace('"', '')
        self.assertEqual(
            'Invalid record _invalid.invalid.records.\n  - invalid name for SRV record',
            reason,
        )

        # Records are not to RFC, but load anyhow (lenient=True)
        invalid = Zone('invalid.records.', [])
        self.source.populate(invalid, lenient=True)
        self.assertEqual(12, len(invalid.records))

    def test_list_zones(self):
        source = ZoneFileSource('test', './tests/zones')
        self.assertEqual(
            ['2.0.192.in-addr.arpa.', 'unit.tests.'], list(source.list_zones())
        )

    @patch('octodns_bind.listdir')
    def test_list_zones_empty_extension(self, listdir_mock):
        listdir_mock.side_effect = [
            ('invalid.records', 'invalid.zone', 'unit.tests')
        ]
        source = ZoneFileSource('test', './tests/zones', file_extension='')
        self.assertEqual(
            ['invalid.records.', 'invalid.zone.', 'unit.tests.'],
            list(source.list_zones()),
        )

    def test_list_zones_custon_extension(self):
        source = ZoneFileSource('test', './tests/zones', file_extension='.tst')
        self.assertEqual(
            ['invalid.records.', 'invalid.zone.', 'unit.tests.'],
            list(source.list_zones()),
        )

    @patch('octodns_bind.ZoneFileProvider._serial')
    def test_apply(self, serial_mock):
        serial_mock.side_effect = [424344, 454647, 484950]

        with TemporaryDirectory() as td:
            provider = ZoneFileProvider('target', td.dirname)

            # no root NS
            desired = Zone('unit.tests.', [])

            # populate as a target, shouldn't find anything, file wouldn't even
            # exist
            provider.populate(desired, target=True)
            self.assertEqual(0, len(desired.records))

            cname = Record.new(
                desired,
                'cname',
                {'type': 'CNAME', 'ttl': 42, 'value': 'target.unit.tests.'},
            )
            desired.add_record(cname)

            changes = [Create(cname)]
            plan = Plan(None, desired, changes, True)
            provider._apply(plan)

            with open(join(td.dirname, 'unit.tests.')) as fh:
                self.assertEqual(
                    '''$ORIGIN unit.tests.

@ 3600 IN SOA ns.unit.tests. webmaster.unit.tests. (
    424344 ; Serial
    3600 ; Refresh
    600 ; Retry
    604800 ; Expire
    3600 ; NXDOMAIN ttl
)

cname       42 IN CNAME    target.unit.tests.
''',
                    fh.read(),
                )

            # add a subdirectory
            provider.directory += '/subdir'

            # with a NS this time
            ns = Record.new(
                desired,
                '',
                {
                    'type': 'NS',
                    'ttl': 43,
                    'values': ('ns1.unit.tests.', 'ns2.unit.tests.'),
                },
            )
            desired.add_record(ns)
            # and a second record with the same name (apex)
            a = Record.new(
                desired, '', {'type': 'A', 'ttl': 44, 'value': '1.2.3.4'}
            )
            desired.add_record(a)

            plan.changes = [Create(a), Create(ns)] + plan.changes
            provider._apply(plan)

            with open(join(td.dirname, 'subdir', 'unit.tests.')) as fh:
                self.assertEqual(
                    '''$ORIGIN unit.tests.

@ 3600 IN SOA ns1.unit.tests. webmaster.unit.tests. (
    454647 ; Serial
    3600 ; Refresh
    600 ; Retry
    604800 ; Expire
    3600 ; NXDOMAIN ttl
)

@           44 IN A        1.2.3.4
            43 IN NS       ns1.unit.tests.
            43 IN NS       ns2.unit.tests.
cname       42 IN CNAME    target.unit.tests.
''',
                    fh.read(),
                )

            # TXT record rrdata's are quoted
            txt = Record.new(
                desired,
                'txt',
                {'type': 'TXT', 'ttl': 45, 'value': 'hello " world'},
            )
            desired.add_record(txt)

            # test out customizing the SOA details
            provider.default_ttl = 3602
            provider.refresh = 3601
            provider.retry = 601
            provider.expire = 604801
            provider.nxdomain = 3601

            plan.changes = [Create(txt), Create(ns)]
            provider._apply(plan)
            with open(join(td.dirname, 'subdir', 'unit.tests.')) as fh:
                self.assertEqual(
                    '''$ORIGIN unit.tests.

@ 3602 IN SOA ns1.unit.tests. webmaster.unit.tests. (
    484950 ; Serial
    3601 ; Refresh
    601 ; Retry
    604801 ; Expire
    3601 ; NXDOMAIN ttl
)

@         43 IN NS       ns1.unit.tests.
          43 IN NS       ns2.unit.tests.
txt       45 IN TXT      "hello \\" world"
''',
                    fh.read(),
                )

    def test_primary_nameserver(self):
        # no records (thus no root NS records) we get the placeholder
        self.assertEqual(
            'ns.unit.tests.', self.source._primary_nameserver('unit.tests.', [])
        )

        class FakeNsRecord:
            def __init__(self, name, values):
                self.name = name
                self.values = values
                self._type = 'NS'

        # has non-root NS record, placeholder
        self.assertEqual(
            'ns.unit.tests.',
            self.source._primary_nameserver(
                'unit.tests.', [FakeNsRecord('not-root', ['xx.unit.tests.'])]
            ),
        )

        # has root NS record
        self.assertEqual(
            'ns1.unit.tests.',
            self.source._primary_nameserver(
                'unit.tests.',
                [
                    FakeNsRecord('not-root', ['xx.unit.tests.']),
                    FakeNsRecord('', ['ns1.unit.tests.', 'ns2.unit.tests.']),
                ],
            ),
        )

    def test_hostmaster_email(self):
        # default constructed
        self.assertEqual(
            'webmaster.unit.tests.',
            self.source._hostmaster_email('unit.tests.'),
        )

        # overridden just username
        source = ZoneFileProvider('test', '.', hostmaster_email='altusername')
        self.assertEqual(
            'altusername.unit.tests.', source._hostmaster_email('unit.tests.')
        )

        # overridden username with .
        source = ZoneFileProvider('test', '.', hostmaster_email='alt.username')
        self.assertEqual(
            'alt\\.username.other.tests.',
            source._hostmaster_email('other.tests.'),
        )

        # overridden full email addr
        source = ZoneFileProvider(
            'test', '.', hostmaster_email='root@some.com.'
        )
        self.assertEqual(
            'root.some.com.', source._hostmaster_email('ignored.tests.')
        )

        # overridden full email addr no trailing .
        source = ZoneFileProvider('test', '.', hostmaster_email='root@some.com')
        self.assertEqual(
            'root.some.com', source._hostmaster_email('ignored.tests.')
        )

    def test_longest_name(self):
        # make sure empty doesn't blow up and we get 0
        self.assertEqual(0, self.source._longest_name([]))

        class FakeRecord:
            def __init__(self, name):
                self.name = name

        self.assertEqual(
            4,
            self.source._longest_name(
                [
                    FakeRecord(''),
                    FakeRecord('1'),
                    FakeRecord('12'),
                    FakeRecord('123'),
                    FakeRecord('1234'),
                ]
            ),
        )

    @patch('octodns_bind.ZoneFileProvider._now')
    def test_serial(self, now_mock):
        class FakeDatetime:
            def __init__(self, timestamp):
                self._timestamp = timestamp

            def timestamp(self):
                return self._timestamp

        now_mock.side_effect = [
            # simple
            FakeDatetime(42),
            # real
            FakeDatetime(1694231210),
            # max
            FakeDatetime(2147483647),
            # max + 1
            FakeDatetime(2147483647 + 1),
            # max + 2
            FakeDatetime(2147483647 + 2),
        ]
        self.assertEqual(42, self.source._serial())
        self.assertEqual(1694231210, self.source._serial())
        self.assertEqual(0, self.source._serial())
        self.assertEqual(1, self.source._serial())

    def test_now(self):
        # smoke test
        self.assertTrue(self.source._now())


class TestRfc2136Provider(TestCase):
    def test_host_ip(self):
        provider = Rfc2136Provider('test', '192.0.2.1')
        self.assertEqual('192.0.2.1', provider.host)

    @patch('socket.getaddrinfo')
    def test_host_dns(self, resolve_mock):
        host, ipv4, ipv6 = 'axfr.unit.tests.', '192.0.2.2', '2001:db8::1'

        # Query success IPv4
        resolve_mock.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ipv4, 0))
        ]
        provider = Rfc2136Provider('test', host)
        self.assertEqual(ipv4, provider.host)

        # Query success IPv6
        resolve_mock.reset_mock()
        resolve_mock.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', (ipv6, 0, 0, 0))
        ]
        provider = Rfc2136Provider('test', host, ipv6=True)
        self.assertEqual(ipv6, provider.host)

        # Query failure
        resolve_mock.reset_mock()
        resolve_mock.side_effect = OSError
        with self.assertRaises(AxfrSourceZoneTransferFailed):
            provider = Rfc2136Provider('test', host)

    def test_auth(self):
        provider = Rfc2136Provider('test', '127.0.0.1')
        self.assertEqual({}, provider._auth_params())

        key_secret = 'vZew5TtZLTZKTCl00xliGt+1zzsuLWQWFz48bRbPnZU='
        provider = Rfc2136Provider(
            'test',
            '127.0.0.1',
            key_name='key-name',
            key_secret=key_secret,
            key_algorithm='hmac-sha1',
        )
        self.assertTrue('keyring' in provider._auth_params())
        self.assertTrue('keyalgorithm' in provider._auth_params())

    @patch('dns.update.Update.delete')
    @patch('dns.update.Update.replace')
    @patch('dns.update.Update.add')
    @patch('dns.query.tcp')
    @patch('octodns_bind.AxfrPopulate.zone_records')
    def test_apply(
        self,
        zone_records_mock,
        dns_query_tcp_mock,
        add_mock,
        replace_mock,
        delete_mock,
    ):
        provider = Rfc2136Provider('test', '127.0.0.1')

        desired = Zone('unit.tests.', [])
        record = Record.new(
            desired, 'a', {'type': 'A', 'ttl': 42, 'value': '1.2.3.4'}
        )
        desired.add_record(record)

        def reset():
            zone_records_mock.reset_mock()
            dns_query_tcp_mock.reset_mock()
            add_mock.reset_mock()
            replace_mock.reset_mock()
            delete_mock.reset_mock()
            dns_query_tcp_mock.return_value = dns.message.Message()

        # create
        reset()
        zone_records_mock.side_effect = [[]]
        plan = provider.plan(desired)
        self.assertTrue(plan)
        provider.apply(plan)
        dns_query_tcp_mock.assert_called_once()
        add_mock.assert_called_with('a.unit.tests.', 42, 'A', '1.2.3.4')
        replace_mock.assert_not_called()
        delete_mock.assert_not_called()

        # update with error
        reset()
        error_result = dns.message.Message()
        error_result.set_rcode(dns.rcode.REFUSED)
        dns_query_tcp_mock.return_value = error_result
        zone_records_mock.side_effect = [
            [Rr('a.unit.tests.', 'A', 42, '2.3.4.5')]
        ]
        plan = provider.plan(desired)
        self.assertTrue(plan)
        self.assertRaises(Rfc2136ProviderUpdateFailed, provider.apply, plan)
        dns_query_tcp_mock.assert_called_once()
        replace_mock.assert_called_with('a.unit.tests.', 42, 'A', '1.2.3.4')
        add_mock.assert_not_called()
        delete_mock.assert_not_called()

        # update
        reset()
        zone_records_mock.side_effect = [
            [Rr('a.unit.tests.', 'A', 42, '2.3.4.5')]
        ]
        plan = provider.plan(desired)
        self.assertTrue(plan)
        provider.apply(plan)
        dns_query_tcp_mock.assert_called_once()
        replace_mock.assert_called_with('a.unit.tests.', 42, 'A', '1.2.3.4')
        add_mock.assert_not_called()
        delete_mock.assert_not_called()

        # delete
        reset()
        desired = Zone('unit.tests.', [])
        zone_records_mock.side_effect = [
            [Rr('a.unit.tests.', 'A', 42, '2.3.4.5')]
        ]
        plan = provider.plan(desired)
        self.assertTrue(plan)
        provider.apply(plan)
        dns_query_tcp_mock.assert_called_once()
        delete_mock.assert_called_with('a.unit.tests.', 'A', '2.3.4.5')
        add_mock.assert_not_called()
        replace_mock.assert_not_called()
