"""The one response that changes a real system, and the commands an analyst can run by hand.

Real mode is off unless ALLSAFE_REAL_RESPONSE=1. With it on, ALLSAFE can add a Windows Firewall rule on this
machine that blocks one public address. response_engine only calls this after a person has approved that
action and clicked run. Stopping processes and changing accounts never run from here: those are shown as
commands, for an analyst to read, check and run.
"""
import ipaddress
import logging
import os
import re
import socket
import subprocess

from utils.normalizer import clean_ip, is_internal_ip

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT_SECONDS = 15
# Blocking a resolver would take this machine off the internet
PUBLIC_RESOLVERS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220'}
# A value from a log goes into a command only if it cannot be anything else: no spaces, quotes or pipes, and no leading dash
_PLAIN_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')


class RealResponseError(Exception):
    """This machine could not do it. The message is safe to show to the client."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def enabled():
    return os.environ.get('ALLSAFE_REAL_RESPONSE') == '1' and os.environ.get('ALLSAFE_PUBLIC_DEMO') != '1'


def _is_windows():
    return os.name == 'nt'


def is_administrator():
    if not _is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def not_ready_reason():
    if not _is_windows():
        return 'Real mode only supports Windows Firewall, and this machine does not run Windows. Use the commands instead.'
    if not is_administrator():
        return 'ALLSAFE is not running as administrator, so Windows Firewall would refuse the rule. Start it from an Administrator terminal.'
    return None


def status():
    """What the page says about real mode"""
    if not enabled():
        return {'enabled': False, 'ready': False, 'reason': 'Real mode is off. Set ALLSAFE_REAL_RESPONSE=1 and restart to turn it on.'}
    reason = not_ready_reason()
    return {'enabled': True, 'ready': reason is None, 'reason': reason}


def _run(arguments):
    # A list and no shell, so that nothing in an argument can become a second command
    try:
        return subprocess.run(arguments, capture_output=True, text=True, errors='replace', timeout=COMMAND_TIMEOUT_SECONDS,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.SubprocessError) as error:
        logger.warning('Could not run %s: %s', arguments[0], error)
        raise RealResponseError('Windows Firewall could not be reached.')


def _firewall(*arguments):
    return _run(['netsh', 'advfirewall', 'firewall', *arguments])


def rule_name(ip):
    return f'ALLSAFE-block-{ip}'


def _this_machines_addresses():
    """Its own addresses and DNS servers. Blocking either would cut it off."""
    addresses = set()
    try:
        addresses.update(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None))
    except OSError:
        pass
    try:
        addresses.update(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', _run(['netsh', 'interface', 'ip', 'show', 'dnsservers']).stdout))
    except RealResponseError:
        pass
    return addresses


def refusal_reason(target, protected_targets=()):
    """Why this address must not be blocked for real, or None"""
    ip = clean_ip(target)
    if not ip:
        return 'This is not an IP address, so it cannot be blocked.'
    if ip in protected_targets:
        return f'{ip} is a protected target and cannot be acted on'
    address = ipaddress.ip_address(ip)
    if is_internal_ip(ip) or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return f'{ip} is an internal or special address. Blocking it for real could cut this machine off from its own network.'
    if ip in PUBLIC_RESOLVERS or ip in _this_machines_addresses():
        return f'{ip} is a DNS server or an address of this machine. Blocking it could take this machine offline.'
    return None


def _first_line(outcome):
    lines = [line.strip() for line in f'{outcome.stdout}\n{outcome.stderr}'.splitlines() if line.strip()]
    return lines[0][:200] if lines else 'No reason was given.'


def rule_exists(ip):
    return _firewall('show', 'rule', f'name={rule_name(ip)}').returncode == 0


def block(ip):
    """Block all traffic with this address, in and out. Raises RealResponseError if that failed."""
    reason = not_ready_reason()
    if reason:
        raise RealResponseError(reason)
    if rule_exists(ip):
        return
    name = rule_name(ip)
    for direction in ('in', 'out'):
        outcome = _firewall('add', 'rule', f'name={name}', f'dir={direction}', 'action=block', f'remoteip={ip}')
        if outcome.returncode != 0:
            # All or nothing: a rule for one direction alone would look like a block and not be one
            _firewall('delete', 'rule', f'name={name}')
            raise RealResponseError(f'Windows Firewall refused the rule: {_first_line(outcome)}')


def unblock(ip):
    """Remove the rules again. Raises RealResponseError if they are still there."""
    reason = not_ready_reason()
    if reason:
        raise RealResponseError(reason)
    outcome = _firewall('delete', 'rule', f'name={rule_name(ip)}')
    if rule_exists(ip):
        raise RealResponseError(f'Windows Firewall kept the rule: {_first_line(outcome)}')


def _plain_name(value):
    """A name from a log, if it is safe in a command that someone will paste. A domain prefix is dropped."""
    text = str(value or '').strip().rsplit('\\', 1)[-1]
    return text if _PLAIN_NAME.match(text) else None


def _ip_tables(ip):
    return 'ip6tables' if ':' in ip else 'iptables'


def _stem(name):
    return name[:-4] if name.lower().endswith('.exe') else name


def manual_commands(action_type, target):
    """The real commands for an action, with its target filled in. None if the target cannot go in a command safely."""
    value = clean_ip(target) if action_type in ('investigate_source_ip', 'block_test_ip') else _plain_name(target)
    if not value:
        return None
    if action_type == 'block_test_ip':
        name, tables = rule_name(value), _ip_tables(value)
        return {
            'note': 'Run as administrator on the machine to protect. All traffic with this address stops, including any legitimate traffic.',
            'windows': [f'netsh advfirewall firewall add rule name="{name}" dir=in action=block remoteip={value}',
                        f'netsh advfirewall firewall add rule name="{name}" dir=out action=block remoteip={value}'],
            'windows_undo': [f'netsh advfirewall firewall delete rule name="{name}"'],
            'linux': [f'sudo {tables} -I INPUT -s {value} -j DROP', f'sudo {tables} -I OUTPUT -d {value} -j DROP'],
            'linux_undo': [f'sudo {tables} -D INPUT -s {value} -j DROP', f'sudo {tables} -D OUTPUT -d {value} -j DROP'],
        }
    if action_type == 'disable_test_account':
        return {
            'note': 'Run as administrator on the machine that holds this account. The owner and any service using it lose access. A domain account is disabled on the domain controller instead.',
            'windows': [f'net user {value} /active:no'],
            'windows_undo': [f'net user {value} /active:yes'],
            'linux': [f'sudo usermod -L {value}'],
            'linux_undo': [f'sudo usermod -U {value}'],
        }
    if action_type == 'terminate_test_process':
        stem = _stem(value)
        return {
            'note': 'Check what is running first, because this stops every process with this name. It cannot be undone, and unsaved work in the process is lost.',
            'windows': [f'tasklist /V /FI "IMAGENAME eq {value}"', f'taskkill /IM {value} /F'],
            'windows_undo': [],
            'linux': [f'pgrep -a -x {stem}', f'sudo pkill -x {stem}'],
            'linux_undo': [],
        }
    if action_type == 'investigate_source_ip':
        return {
            'note': 'These only read. They show current connections with this address, and its name if it has one.',
            'windows': [f'netstat -ano | findstr {value}', f'nslookup {value}'],
            'windows_undo': [],
            'linux': [f'ss -tunap | grep {value}', f'nslookup {value}'],
            'linux_undo': [],
        }
    if action_type == 'review_account':
        return {
            'note': 'These only read. Run them on the machine that holds this account.',
            'windows': [f'net user {value}'],
            'windows_undo': [],
            'linux': [f'id {value}', f'last -n 20 {value}'],
            'linux_undo': [],
        }
    if action_type == 'inspect_process':
        return {
            'note': 'These only read. They show the process, its owner and how it was started.',
            'windows': [f'tasklist /V /FI "IMAGENAME eq {value}"'],
            'windows_undo': [],
            'linux': [f'ps -C {_stem(value)} -o pid,ppid,user,cmd'],
            'linux_undo': [],
        }
    if action_type == 'collect_additional_logs':
        return {
            'note': f'Run as administrator on {value}. These read the logs, and save a copy in the current folder.',
            'windows': [f'wevtutil qe Security /c:500 /rd:true /f:text > allsafe-{value}.txt'],
            'windows_undo': [],
            'linux': [f'sudo journalctl -n 500 > allsafe-{value}.log'],
            'linux_undo': [],
        }
    return None
