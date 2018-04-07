#!/usr/bin/env python3

import unittest
from unittest.mock import patch, call
import subprocess

import buildd

_WB_LIST_OUTPUT = subprocess.CompletedProcess(
    args=[],
    returncode=0,
    stdout=b"""\
amd64/sid/chasquid_0.04-1 [optional:out-of-date:calprio{45}:days{0}]
amd64/sid/python3.6_3.6.4-4 [optional:out-of-date:calprio{44}:days{0}]
""")
_WB_LIST_EMPTY_OUTPUT = subprocess.CompletedProcess(
    args=[], returncode=0, stdout=b'')
_WB_TAKE_OUTPUT = subprocess.CompletedProcess(
    args=[],
    returncode=0,
    stdout=b"""\
---
-
  calligra:
    -
      status: ok
    -
      pkg-ver: chasquid_0.04-1
    -
      suite: sid
    -
      arch: amd64
    -
      archive: debian
    -
      build_dep_resolver: aptitude
    -
      mail_logs: logs@example.com
""")
_WB_TAKE_FAILED_OUTPUT = subprocess.CompletedProcess(
    args=[],
    returncode=0,
    stdout=b"""\
- gobby:
    - status: not ok
    - reason: "is up-to-date in the archive; doesn't need rebuilding"
""")
# B424EB74051F4844 is a key that expired a long time ago and should
# hence never be picked. DFE4C0B481F37BDB is the reference key that
# is still active at the point in time we check. 135DC390E4032D36
# has been generated as the next key to use (and is hence already
# valid).
_GPG_KEYLIST = """\
sec:e:4096:1:B424EB74051F4844:1398721900:1430257900::u:::sc:::+::::
rvk:::1::::::F75FBFCD771DEB5E9C86050550C3634D3A291CF9:80:
rvk:::17::::::E820094883974FDC3CD00EC699D399A1EC36A185:80:
rvk:::1::::::E5E52560DD91C556DDBDA5D02064C53641C25E5D:80:
fpr:::::::::091BC8E250417B2041F990ACB424EB74051F4844:
grp:::::::::2FF5C26CCC68B2EB11D375867645326471566E1B:
uid:e::::1398721900::846EE2E487D23670F70426952DD6DBEC80B2CE92::buildd key <buildd_arch-hostname@example.com>:
sec:e:4096:1:DFE4C0B481F37BDB:1468787574:1500323574::u:::sc:::+::::
rvk:::1::::::F75FBFCD771DEB5E9C86050550C3634D3A291CF9:80:
rvk:::1::::::010BF4B922AC26888C4F895F49BB63F18B4CCAD5:80:
rvk:::1::::::E5E52560DD91C556DDBDA5D02064C53641C25E5D:80:
rvk:::1::::::77462642A9EF94FD0F77196DBA9C78061DDD8C9B:80:
fpr:::::::::4881416785E6EE2DB59A5C72DFE4C0B481F37BDB:
grp:::::::::FB514081A41735566929601BD58899ABAFA56139:
uid:e::::1468787574::846EE2E487D23670F70426952DD6DBEC80B2CE92::buildd key <buildd_arch-hostname@example.com>:
sec:u:4096:1:135DC390E4032D36:1499637849:1531173849::u:::scSC:::+::::
fpr:::::::::69C17C61AF2936B6C0FD18C4135DC390E4032D36:
grp:::::::::7FFC1B09E39CCB591264F8B8D708B0A624526ACD:
uid:u::::1499637849::846EE2E487D23670F70426952DD6DBEC80B2CE92::buildd key <buildd_arch-hostname@example.com>:
"""
_MOCK_DEFAULT_KEY = buildd.Key(
        keyid='DFE4C0B481F37BDB',
        expiry=0,
        email='buildd_arch-hostname@example.com')


class BuilderTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            'architectures': 'amd64 i386',
            'distributions': 'sid experimental',
        }
        self.builder = buildd.Builder(self.config)

    @patch('subprocess.run', side_effect=[_WB_LIST_OUTPUT, _WB_TAKE_OUTPUT])
    @patch('buildd._pick_gpg_key', return_value='ABCDEF1234567890')
    def test_builds(self, mock_pick_gpg_key, mock_run):
        pkg = next(self.builder.builds())
        mock_run.assert_has_calls([
            call(
                args=self.builder._default_wannabuild_call +
                ['--arch=amd64', '--dist=sid', '--list=needs-build'],
                stdout=subprocess.PIPE),
            call(
                args=self.builder._default_wannabuild_call + [
                    '--arch=amd64', '--dist=sid', '--take',
                    'amd64/sid/chasquid_0.04-1'
                ],
                stdout=subprocess.PIPE),
        ])
        self.assertEqual(pkg.architecture, 'amd64')
        self.assertEqual(pkg.distribution, 'sid')
        self.assertEqual(pkg.source_package, 'chasquid')
        self.assertEqual(pkg.version, '0.04-1')
        self.assertEqual(pkg.archive, 'debian')
        self.assertEqual(pkg.build_dep_resolver, 'aptitude')
        self.assertEqual(pkg.mail_logs, 'logs@example.com')

    @patch(
        'subprocess.run',
        side_effect=[
            _WB_LIST_OUTPUT, _WB_TAKE_FAILED_OUTPUT, _WB_LIST_OUTPUT,
            _WB_TAKE_OUTPUT
        ])
    @patch('buildd._pick_gpg_key', return_value=_MOCK_DEFAULT_KEY)
    def test_builds_take_failed(self, mock_pick_gpg_key, mock_run):
        pkg = next(self.builder.builds())
        self.assertEqual(pkg.source_package, 'chasquid')

    @patch('subprocess.run', side_effect=[_WB_LIST_EMPTY_OUTPUT] * 4)
    @patch('buildd._pick_gpg_key', return_value=_MOCK_DEFAULT_KEY)
    def test_builds_empty_output(self, mock_pick_gpg_key, mock_run):
        self.assertEqual(next(self.builder.builds()), None)

    def test_email_addresses(self):
        builder = buildd.Builder(self.config, hostname='host')
        pkg = buildd.Package(builder, 'pkg', {'pkg-ver': 'pkg_1.2-3',
                                              'arch': 'arch'})
        self.assertEqual(
            'arch Build Daemon (host) <buildd_arch-host@buildd.debian.org>',
            pkg.maintainer_email(buildd.Key(email='buildd_arch-host@buildd.debian.org')))
        with patch('getpass.getuser', return_value='user'):
            self.assertEqual('buildd on host <user@host>',
                             builder._mail_from_email)

    @patch('buildd._pick_gpg_key', return_value=_MOCK_DEFAULT_KEY)
    def test_construct_sbuild_cmd(self, mock_pick_gpg_key):
        builder = buildd.Builder(self.config, hostname='host')
        pkg = buildd.Package(builder, 'pkg', {'pkg-ver': 'pkg_1.2-3',
                                              'arch': 'arch',
                                              'suite': 'sid',
                                              'extra-depends': 'glibc (>> 1)'})
        cmd = builder._construct_sbuild_cmd(pkg)
        self.assertEqual('sbuild', cmd[0])
        self.assertIn('--dist=sid', cmd)
        self.assertIn('--maintainer=arch Build Daemon (host) '
                      '<buildd_arch-hostname@example.com>', cmd)
        self.assertIn('--keyid=DFE4C0B481F37BDB', cmd)
        self.assertIn('--add-depends=glibc (>> 1)', cmd)


class BuilddTest(unittest.TestCase):
    def test_gpg_key_selection(self):
        # Two active keys. Picks the one with the smallest TTL.
        with patch('time.time', return_value=1500000000):
            key = buildd._pick_gpg_key(_GPG_KEYLIST)
            self.assertEqual('DFE4C0B481F37BDB', key.keyid)
            self.assertEqual(1500323574.0-1500000000, key.expiry)
            self.assertEqual('buildd_arch-hostname@example.com', key.email)
        # One active key some time later.
        with patch('time.time', return_value=1518458890.395519):
            key = buildd._pick_gpg_key(_GPG_KEYLIST)
            self.assertEqual('135DC390E4032D36', key.keyid)
            self.assertEqual(1531173849-1518458890.395519, key.expiry)
            self.assertEqual('buildd_arch-hostname@example.com', key.email)
        # A year later: no active key.
        with patch('time.time', return_value=1549994890.395519):
            self.assertEqual(None, buildd._pick_gpg_key(_GPG_KEYLIST))


if __name__ == '__main__':
    unittest.main()
