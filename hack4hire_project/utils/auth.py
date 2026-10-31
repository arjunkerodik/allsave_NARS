"""Optional user accounts. With no active account the dashboard stays limited to this machine, as
before. Once one exists, every page and API needs a login, and analyst names come from the account."""
import threading
import time

from flask import session
from werkzeug.security import check_password_hash, generate_password_hash

import models

ROLES = ('viewer', 'analyst')
MIN_PASSWORD_LENGTH = 10
MAX_FAILED_LOGINS = 5
LOCK_SECONDS = 300
_ENABLED_CACHE_SECONDS = 5
# Answers to a wrong username take as long as those to a wrong password
_DUMMY_HASH = generate_password_hash('allsafe-no-such-user')

_enabled_cache = {'database': None, 'checked_at': 0.0, 'enabled': False}
_failures = {}
_lock = threading.Lock()


def auth_enabled():
    """Checked on every request, so it is cached briefly"""
    now = time.monotonic()
    if _enabled_cache['database'] != models.DATABASE_NAME or now - _enabled_cache['checked_at'] > _ENABLED_CACHE_SECONDS:
        _enabled_cache.update(database=models.DATABASE_NAME, checked_at=now, enabled=models.count_active_users() > 0)
    return _enabled_cache['enabled']


def forget_enabled_state():
    _enabled_cache['database'] = None


def validate_new_account(username, password, role):
    username = str(username or '').strip()
    if not username or len(username) > 64 or any(ch.isspace() for ch in username):
        raise ValueError('Username must be 1 to 64 characters with no spaces')
    if len(str(password or '')) < MIN_PASSWORD_LENGTH:
        raise ValueError(f'Password must have at least {MIN_PASSWORD_LENGTH} characters')
    if role not in ROLES:
        raise ValueError(f"Role must be one of {', '.join(ROLES)}")
    return username


def create_account(username, password, role):
    username = validate_new_account(username, password, role)
    models.save_user(username, generate_password_hash(password), role)
    forget_enabled_state()
    return username


def current_user():
    """The logged-in account, checked against the database so a disabled one stops working at once"""
    name = session.get('user')
    if not name:
        return None
    user = models.get_user(name)
    if not user or user['disabled']:
        session.clear()
        return None
    return {'username': user['username'], 'role': user['role']}


def _lock_remaining(key):
    with _lock:
        entry = _failures.get(key)
        if entry and entry['until'] > time.monotonic():
            return int(entry['until'] - time.monotonic()) + 1
    return 0


def _note_failure(key):
    with _lock:
        entry = _failures.setdefault(key, {'count': 0, 'until': 0.0})
        entry['count'] += 1
        if entry['count'] >= MAX_FAILED_LOGINS:
            entry.update(count=0, until=time.monotonic() + LOCK_SECONDS)


def log_in(username, password, client_ip):
    """Returns (user, error message, HTTP status). The message never says which part was wrong."""
    username = str(username or '').strip()[:64]
    key = (username.lower(), client_ip)
    remaining = _lock_remaining(key)
    if remaining:
        return None, f'Too many failed attempts. Try again in {remaining} seconds.', 429
    user = models.get_user(username)
    valid = check_password_hash(user['password_hash'] if user else _DUMMY_HASH, str(password or ''))
    if not user or user['disabled'] or not valid:
        _note_failure(key)
        return None, 'Wrong username or password.', 401
    with _lock:
        _failures.pop(key, None)
    session.clear()
    session['user'] = user['username']
    session.permanent = True
    models.record_user_login(user['username'])
    return {'username': user['username'], 'role': user['role']}, None, 200
