#!/usr/bin/env python3
# vim:set et ts=4 sw=4:
"""buildd schedules builds on the current machine.

This binary continuously polls for next builds to be run, takes them from
the queue, and runs the build software locally. By design it is not a
daemon and it relies on outside supervision to run continously. This
makes some design decisions like restarting liberally easier to fathom.
"""

from typing import Dict, Iterator, List, Optional, Tuple

import collections
import configparser
import email.utils
import getpass
import logging
import os
import platform
import shutil
import signal
import socket
import subprocess
import threading
import time

from retrying import retry
import yaml

_ARCHIVE_TO_DUPLOAD_TARGET = {
    'debian': 'rsync-ftp-master',
    'debian-security': 'rsync-security',
    'debian-ports': 'rsync-ports',
}


class Key:
    def __init__(self, keyid: str, expiry: Optional[float]=None, email: Optional[str]=None) -> None:
        self.keyid = keyid
        self.expiry = expiry
        self.email = email


class KeyNotFoundError(Exception):
    pass


class Package:
    build_dep_resolver = None  # type: Optional[str]
    mail_logs = None  # type: Optional[str]
    binnmu = None  # type: Optional[int]
    binnmu_changelog = None  # type: Optional[str]
    extra_depends = None  # type: Optional[str]
    extra_conflicts = None  # type: Optional[str]

    # _FIELD_MAP maps YAML fields as returned by wanna-build's take operation
    # to attributes on the object.
    _FIELD_MAP = {
        'build_dep_resolver': 'build_dep_resolver',
        'mail_logs': 'mail_logs',
        'binNMU': 'binnmu',
        'extra-changelog': 'binnmu_changelog',
        'extra-depends': 'extra_depends',
        'extra-conflicts': 'extra_conflicts',
    }

    def __init__(self, builder, name: str, fields: Dict[str, str]) -> None:
        self.builder = builder
        self.name = name
        self.source_package, self.source_version = fields['pkg-ver'].split('_', 2)
        self.epochless_source_version = self.source_version.split(':')[
            1] if ':' in self.source_version else self.source_version
        self.archive = fields['archive']
        self.architecture = fields['arch']
        self.distribution = fields['suite']
        for yaml_field, attr_name in self._FIELD_MAP.items():
            setattr(self, attr_name, fields[yaml_field]
                    if yaml_field in fields else None)

        self.binary_version = self.source_version
        self.epochless_binary_version = self.epochless_source_version
        if self.binnmu:
            binnmu_suffix = '+b{}'.format(self.binnmu)
            self.binary_version += binnmu_suffix
            self.epochless_binary_version += binnmu_suffix

        self.source_package_version = \
            '{p.source_package}_{p.source_version}'.format(p=self)
        self.source_package_binary_version = \
            '{p.source_package}_{p.binary_version}'.format(p=self)
        self.changes_file = \
            '{p.source_package}_{p.epochless_binary_version}_{p.architecture}.changes' \
                .format(p=self)

    def __str__(self):
        return self.source_package_binary_version

    def maintainer_email(self, key: Key):
        return self.builder.maintainer_email_template.format(
            pkg=self, builder=self.builder, key=key)


def _run(args: List[str], check: bool = False) -> Tuple[int, str]:
    """Wrap subprocess.run to enable check/encoding on Python 3.5."""
    result = subprocess.run(args=args, stdout=subprocess.PIPE)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args)
    return result.returncode, result.stdout.decode('utf-8', 'strict')


def _pick_gpg_key(keylist: Optional[str] = None) -> Key:
    if keylist is None:
        _, keylist = _run(
            args=['gpg', '--with-colons', '--list-secret-keys'], check=True)
    # There might be multiple secret keys available. Most likely some
    # of them are already expired and some are not active yet. As a
    # heuristic pick the key with the closest expiry that is still
    # valid. The assumption is that a key that has a vastly larger
    # expiry is new and might not be active on the archive side yet.
    # Note that this code requires that the expiry is set, which is the
    # case for all of Debian's production keys.
    keys = {}  # type: Dict[str, Key]
    t = time.time()
    last_keyid = None  # type: Optional[str]
    for line in keylist.splitlines():
        if line.startswith('uid:') and last_keyid:
            uid = line.split(':', 10)[9]
            realname, email_address = email.utils.parseaddr(uid)
            keys[last_keyid].email = email_address
            continue
        if not line.startswith('sec:'):
            continue
        parts = line.split(':', 7)
        keyid = parts[4]
        expires = parts[6]
        # Reject keys that are already expired or are due to expire within
        # the next 24h.
        if t + 24 * 60 * 60 > float(expires):
            continue
        keys[keyid] = Key(keyid=keyid, expiry=float(expires) - t)
        last_keyid = keyid
    if not keys:
        raise KeyNotFoundError('No usable GPG key found.')
    keyid = min(keys, key=lambda k: keys[k].expiry)
    return keys[keyid]


class ConfigurationError(RuntimeError):
    """Invalid configuration found.

    This exception is raised when a configuration invariant has been
    violated. Note that some configuration like GPG keys has a time-based
    component to it as well that is continuously retested.
    """


class Builder:
    def __init__(self,
                 config,
                 hostname=socket.getfqdn()):
        self.wb_ssh_user = config.get('wb_ssh_user', 'wb-buildd')
        self.wb_ssh_socket = config.get('wb_ssh_socket',
                                        'buildd.debian.org.ssh')
        self.wb_ssh_host = config.get('wb_ssh_host', 'buildd.debian.org')
        self.architectures = config['architectures'].split(' ')
        self.distributions = config.get('distributions', 'any').split(' ')
        self.idle_sleep_time = config.get('idle_sleep_time', 60)  # seconds
        self.hostname = hostname
        self.short_hostname = hostname.split('.')[0]
        self.maintainer_email_template = config.get(
            'maintainer_email_template',
            '{pkg.architecture} Build Daemon ({builder.short_hostname}) '
            '<{key.email}>')

    @property
    def _mail_from_email(self) -> str:
        return 'buildd on {} <{}@{}>'.format(
            self.hostname.split('.')[0], getpass.getuser(), self.hostname)

    @property
    def _default_wannabuild_call(self) -> List[str]:
        return [
            'ssh', '-l', self.wb_ssh_user, '-S', self.wb_ssh_socket,
            self.wb_ssh_host, 'wanna-build', '--api=2'
        ]

    def _query_wannabuild(self, architecture: str, distribution: str,
                          *command) -> str:
        """Queries wanna-build using SSH and the passed-in command."""
        logging.debug('Querying for %s/%s: %s', architecture, distribution,
                      command)
        return _run(
            args=self._default_wannabuild_call +
            ['--arch=' + architecture, '--dist=' + distribution] +
            list(command),
            check=True)[1]

    def _parse_take_response(self, response: str) -> Optional[Package]:
        """Parses the YAML response from wanna-build's take operation.

        The YAML is pretty awkwardly nested. The code mostly needs to
        unnest the data structure and then construct the proper object
        from it.
        """
        for source_package, descriptor in yaml.safe_load(response)[0].items():
            data = {}  # type: Dict[str, str]
            for elem in descriptor:
                for k, v in elem.items():
                    data[k] = v
            break
        if data['status'] != 'ok':
            return None
        return Package(self, source_package, data)

    def _take(self, line: str) -> Optional[Package]:
        archdistpkgver, _ = line.split(' ', 2)
        arch, dist, pkgver = archdistpkgver.split('/', 3)
        return self._parse_take_response(
            self._query_wannabuild(arch, dist, '--take', archdistpkgver))

    def _get_next_wb(self) -> Optional[Package]:
        """Returns the next package to build or None if there is nothing to do.

        As an interesting twist wanna-build will in API 2-mode return the
        distribution and architecture as part of the package to build. This
        is a traditional loop but in the future wanna-build could also just
        return the next package to build and the code would obey this
        decision regardless of the actual query.
        """
        for dist in self.distributions:
            for arch in self.architectures:
                response = self._query_wannabuild(arch, dist,
                                                  '--list=needs-build')
                pending = response.split('\n')
                if not pending[0]:
                    continue
                result = self._take(pending[0])
                if result:
                    return result
        return None

    def builds(self) -> Iterator[Optional[Package]]:
        """Returns an iterator of packages to build."""
        while True:
            if _pick_gpg_key() is None:
                raise ConfigurationError('No valid GPG signing key found.')
            yield self._get_next_wb()

    def _build_dir(self, pkg: Package):
        return os.path.join(
            os.path.expanduser('~/build'),
            '{p.source_package}_{p.epochless_source_version}'.format(p=pkg))

    def _construct_sbuild_cmd(self, pkg: Package) -> List[str]:
        key = _pick_gpg_key()
        cmd = [
            'sbuild',
            '--apt-update',
            '--no-apt-upgrade',
            '--no-apt-distupgrade',
            '--no-run-lintian',
            '--batch',
            '--dist=' + pkg.distribution,
            '--sbuild-mode=buildd',
            '--mailfrom=' + self._mail_from_email,
            '--maintainer=' + pkg.maintainer_email(key),
            '--keyid=' + key.keyid,
        ]
        if pkg.architecture != 'all':
            cmd.extend(['--arch={}'.format(pkg.architecture), '--no-arch-all'])
        else:
            cmd.extend(['--arch-all', '--no-arch-any'])
        if pkg.build_dep_resolver:
            cmd.append('--build-dep-resolver=' + pkg.build_dep_resolver)
        if pkg.mail_logs:
            cmd.append('--mail-log-to=' + pkg.mail_logs)
        if pkg.binnmu and pkg.binnmu_changelog:
            cmd.append('--binNMU={}'.format(pkg.binnmu))
            cmd.append('--make-binNMU=' + pkg.binnmu_changelog)
        if pkg.extra_depends:
            cmd.append('--add-depends=' + pkg.extra_depends)
        if pkg.extra_conflicts:
            cmd.append('--add-conflicts=' + pkg.extra_conflicts)
        cmd.append(pkg.source_package_version)
        return cmd

    def build(self, pkg: Package):
        """Builds a package using sbuild."""
        logging.info('Building %s...', pkg)
        logging.debug('Metadata: %s', vars(pkg))
        build_dir = self._build_dir(pkg)
        os.makedirs(build_dir, exist_ok=True)
        cmd = self._construct_sbuild_cmd(pkg)
        rc = subprocess.run(cmd, cwd=build_dir).returncode
        if rc == 0:
            logging.info('Build of %s succeeded.', pkg)
            result = 'built'
        elif rc == 2:
            logging.info('Build of %s attempted unsuccessfully.', pkg)
            result = 'attempted'
        else:
            logging.info('Build of %s exited with %d: giving back.', pkg, rc)
            result = 'give-back'
        self._query_wannabuild(
            pkg.architecture,
            pkg.distribution,
            '--' + result,
            pkg.source_package_binary_version)
        return True if result == 'built' else False

    @retry(stop_max_attempt_number=3, wait_fixed=2 * 60 * 1000)
    def _run_dupload(self, target, cwd, filename):
        try:
            subprocess.run(
                ['dupload', '--to', target, filename], check=True, cwd=cwd)
        except:
            # retrying has a logger attribute but the version in Debian
            # Stretch is too old.
            logging.exception('Failed to call dupload successfully.')
            raise

    def upload(self, pkg: Package):
        logging.info('Uploading %s...', pkg)
        if pkg.archive not in _ARCHIVE_TO_DUPLOAD_TARGET:
            logging.error('Could not upload to %s: target not hardcoded.',
                          pkg.archive)
        target = _ARCHIVE_TO_DUPLOAD_TARGET[pkg.archive]

        try:
            self._run_dupload(
                target,
                self._build_dir(pkg),
                pkg.changes_file)
            self._query_wannabuild(
                pkg.architecture,
                pkg.distribution,
                '--uploaded',
                pkg.source_package_binary_version)
        except:
            self._query_wannabuild(
                pkg.architecture,
                pkg.distribution,
                '--give-back',
                pkg.source_package_binary_version)
            raise

    def cleanup(self, pkg: Package):
        if os.path.exists(self._build_dir(pkg)):
            shutil.rmtree(self._build_dir(pkg))


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)-15s %(levelname)-8s %(message)s')
    os.environ['DEB_BUILD_OPTIONS'] = 'parallel={}'.format(
        len(os.sched_getaffinity(0)))
    config = configparser.ConfigParser()
    config.read(['/etc/buildd.conf', os.path.expanduser('~/.buildd.conf')])
    buildd_config = config['buildd'] if 'buildd' in config else {}
    builder = Builder(buildd_config)

    exit = threading.Event()
    def trigger_eventual_exit(signum, frame):
        logging.info('Signal to exit received.')
        exit.set()
    signal.signal(signal.SIGUSR1, trigger_eventual_exit)

    pkgs = builder.builds()
    while True:
        # Bail out early in case we were signalled to exit.
        if exit.is_set():
            logging.info('Exiting due to signal.')
            break

        # Get the next item off the queue. This calls out to wanna-build.
        try:
            pkg = next(pkgs)
        except StopIteration:
            logging.info('No more packages to build; exiting.')
            break

        # If there is nothing to do, back-off for a while.
        if pkg is None:
            logging.info('Nothing to do, sleeping for %d seconds...',
                         builder.idle_sleep_time)
            if not exit.is_set():
                exit.wait(builder.idle_sleep_time)
            continue

        # We have something to do, so let's start building.
        try:
            if builder.build(pkg):
                builder.upload(pkg)
        finally:
            builder.cleanup(pkg)


if __name__ == '__main__':
    main()
