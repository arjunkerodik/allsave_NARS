"""
run_demo.py  –  One-command judge-ready startup for Hack4Hire 2026
==================================================================
Wipes the old database, seeds ALL synthetic attack scenarios,
then starts the Flask server on http://127.0.0.1:5000.

Usage:
    cd hack4hire_project
    python run_demo.py
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DB   = os.path.join(ROOT, 'security_monitoring.db')
SEED = os.path.join(ROOT, 'scripts', 'seed_demo.py')
APP  = os.path.join(ROOT, 'app.py')

print()
print("╔══════════════════════════════════════════════════════╗")
print("║   ALLSAFE SOC Platform  ·  Hack4Hire 2026 Demo       ║")
print("╠══════════════════════════════════════════════════════╣")
print("║  This will:                                          ║")
print("║   1. Reset the database to a clean state             ║")
print("║   2. Seed 11 attack scenarios with synthetic data    ║")
print("║   3. Start the server on http://127.0.0.1:5000       ║")
print("╚══════════════════════════════════════════════════════╝")
print()

# Step 1: Wipe old DB
if os.path.exists(DB):
    os.remove(DB)
    print("  Old database removed.")

# Step 2: Seed demo data
print("  Seeding demo data (this takes ~20 seconds)...")
print()
result = subprocess.run([sys.executable, SEED], cwd=ROOT)
if result.returncode != 0:
    print("\n  WARNING: Seeding had some issues but we will continue.")

print()
print("  Starting server ...")
print()
print("  ► Open http://127.0.0.1:5000")
print("  ► Login: analyst / Analyst@Hack4Hire2026")
print()
print("  Press Ctrl+C to stop the server.")
print()

# Step 3: Start server
os.execv(sys.executable, [sys.executable, APP])

