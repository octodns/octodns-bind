#
#
#

import socket
from os.path import exists
from shutil import copyfile
from unittest import TestCase
from unittest.mock import patch

import dns.resolver
import dns.zone
from dns.exception import DNSException

from octodns.record import Record, Rr, ValidationError
from octodns.zone import Zone

from octodns_bind import (
    AxfrSource,
    AxfrSourceZoneTransferFailed,
    Rfc2136Provider,
    Rfc2136ProviderUpdateFailed,
    ZoneFileSource,
    ZoneFileSourceLoadFailure,
    ZoneFileSourceNotFound,
)


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
