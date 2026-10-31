"""Keeps a demo's live stream moving, by running synthetic scenarios through the real API.

    python scripts/demo_feed.py [--port 5000] [--minutes 120]

Normal activity every 20 seconds, and a synthetic attack every 5 minutes. It only calls this
application on this machine, sends no other traffic, and stops by itself.
"""
import argparse
import time
import urllib.request

ATTACKS = ['brute_force', 'port_scan', 'privilege_escalation', 'lateral', 'suspicious_process', 'cred_dump', 'exfil', 'beacon',
           'webshell', 'credential_abuse', 'account_creation', 'multi_stage']
TICK_SECONDS = 20
ATTACK_EVERY = 15


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--minutes', type=int, default=120)
    args = parser.parse_args()
    for tick in range(args.minutes * 60 // TICK_SECONDS):
        is_attack = tick % ATTACK_EVERY == ATTACK_EVERY - 1
        scenario = ATTACKS[(tick // ATTACK_EVERY) % len(ATTACKS)] if is_attack else 'benign'
        request = urllib.request.Request(f'http://127.0.0.1:{args.port}/api/simulate/{scenario}', data=b'{}',
                                         headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                print(tick, scenario, response.status, flush=True)
        except OSError as error:
            print(tick, scenario, 'failed:', error, flush=True)
        time.sleep(TICK_SECONDS)


if __name__ == '__main__':
    main()
