@echo off
title ALLSAFE SOC - Hack4Hire 2026 Live Deployment
echo ========================================================
echo  Launching ALLSAFE SOC Platform + Live Public Tunnel
echo ========================================================
cd /d "%~dp0"
python deploy_live.py
pause

