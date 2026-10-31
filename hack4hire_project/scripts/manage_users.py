"""Create and manage dashboard accounts. Creating the first one turns login on for the dashboard.

    python scripts/manage_users.py add alice --role analyst
    python scripts/manage_users.py list
    python scripts/manage_users.py disable alice
    python scripts/manage_users.py enable alice

The password is asked for at the prompt, or read from ALLSAFE_NEW_PASSWORD when run unattended.
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import models
from utils.auth import MIN_PASSWORD_LENGTH, ROLES, create_account


def ask_password():
    from_environment = os.environ.get('ALLSAFE_NEW_PASSWORD')
    if from_environment:
        return from_environment
    password = getpass.getpass(f'Password (at least {MIN_PASSWORD_LENGTH} characters): ')
    if password != getpass.getpass('Again: '):
        sys.exit('The passwords do not match.')
    return password


def main():
    parser = argparse.ArgumentParser(description='Manage ALLSAFE dashboard accounts')
    commands = parser.add_subparsers(dest='command', required=True)
    add = commands.add_parser('add', help='Create an account, or reset its password and role')
    add.add_argument('username')
    add.add_argument('--role', choices=ROLES, default='analyst')
    commands.add_parser('list', help='List accounts')
    for name in ('disable', 'enable'):
        commands.add_parser(name, help=f'{name.title()} an account').add_argument('username')
    args = parser.parse_args()

    models.init_db()
    if args.command == 'add':
        try:
            username = create_account(args.username, ask_password(), args.role)
        except ValueError as error:
            sys.exit(str(error))
        models.add_audit_entry('manage_users', 'user_saved', 'user', None, None, {'username': username, 'role': args.role})
        print(f'Saved {username} ({args.role}). Login is now required on the dashboard.')
    elif args.command == 'list':
        for user in models.get_users():
            state = 'disabled' if user['disabled'] else 'active'
            print(f"{user['username']:<24} {user['role']:<10} {state:<10} last login: {user['last_login_at'] or 'never'}")
    else:
        disabled = args.command == 'disable'
        if not models.set_user_disabled(args.username, disabled):
            sys.exit(f'No account named {args.username}.')
        models.add_audit_entry('manage_users', 'user_disabled' if disabled else 'user_enabled', 'user', None, None, {'username': args.username})
        print(f'{args.username} is now {"disabled" if disabled else "enabled"}.')
        if not models.count_active_users():
            print('No active accounts are left, so the dashboard no longer asks for a login. It accepts actions only from this machine.')


if __name__ == '__main__':
    main()
