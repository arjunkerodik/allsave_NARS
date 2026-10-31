"""Checks that real mode can block and unblock on this machine. Run it from an Administrator terminal.

    python scripts/check_real_block.py

It blocks 203.0.113.99, an address reserved for documentation that nothing real uses, reads the
rule back, removes it, and checks that it has gone. The exit code is 0 only if all of that worked.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import real_response  # noqa: E402

TEST_ADDRESS = '203.0.113.99'


def main():
    print(f'Administrator: {real_response.is_administrator()}')
    reason = real_response.refusal_reason(TEST_ADDRESS)
    if reason:
        print(f'FAIL  {reason}')
        return 1
    try:
        real_response.block(TEST_ADDRESS)
        print(f'Rule added: {real_response.rule_name(TEST_ADDRESS)}')
        if not real_response.rule_exists(TEST_ADDRESS):
            print('FAIL  The rule could not be read back.')
            return 1
        print('Rule read back from Windows Firewall.')
        real_response.unblock(TEST_ADDRESS)
        print('Rule removed, and it has gone.')
    except real_response.RealResponseError as error:
        print(f'FAIL  {error.message}')
        return 1
    print('PASS  Real mode can block and unblock on this machine.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
