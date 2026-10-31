"""
deploy_live.py  -  Live Public Deployment with Cloudflare Tunnel
================================================================
Exposes your ALLSAFE Hack4Hire SOC platform to the live internet with
an instant, secure HTTPS URL that judges can access from anywhere.

Usage:
    cd hack4hire_project
    python deploy_live.py
"""

import os
import subprocess
import sys
import time
import re

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = r"C:\Users\arjun\.tools"
CLOUDFLARED = os.path.join(TOOLS_DIR, "cloudflared.exe")

print("=" * 65)
print("  Hack4Hire 2026 - ALLSAFE Public Deployment System")
print("=" * 65)
print()

if not os.path.exists(CLOUDFLARED):
    print("[-] cloudflared.exe not found at", CLOUDFLARED)
    sys.exit(1)

print("[1/2] Checking if local server is active on port 5000...")
import urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:5000/", timeout=3) as res:
        if res.status == 200:
            print("      Local server is ONLINE and responding!")
except Exception:
    print("      Starting local server...")
    subprocess.Popen([sys.executable, os.path.join(ROOT, "app.py")], cwd=ROOT)
    time.sleep(4)

print("[2/2] Launching Cloudflare Tunnel for secure HTTPS access...")
log_path = os.path.join(TOOLS_DIR, "live_tunnel.log")
with open(log_path, "w") as log_file:
    proc = subprocess.Popen(
        [CLOUDFLARED, "tunnel", "--url", "http://127.0.0.1:5000"],
        stdout=log_file,
        stderr=subprocess.STREQ_LOG if hasattr(subprocess, "STREQ_LOG") else log_file,
        text=True
    )

print("      Negotiating edge route...")
tunnel_url = None
for _ in range(30):
    time.sleep(1)
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", content)
            if match:
                tunnel_url = match.group(0)
                break

if tunnel_url:
    print()
    print("*" * 65)
    print("  SUCCESS! YOUR PLATFORM IS LIVE ON THE INTERNET:")
    print()
    print(f"  Public URL :  {tunnel_url}")
    print(f"  Login URL  :  {tunnel_url}/login")
    print(f"  Console    :  {tunnel_url}/dashboard")
    print()
    print("  Analyst Credentials:")
    print("  Username   :  analyst")
    print("  Password   :  Analyst@Hack4Hire2026")
    print("*" * 65)
    print()
    print("Keep this terminal open while judges view the project.")
    print("Press Ctrl+C to terminate the live tunnel.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\nTunnel closed.")
else:
    print("[-] Could not retrieve tunnel URL. Check log at:", log_path)

