@echo off
title WinDiag Pro
echo Installing dependencies (first run only)...
pip install customtkinter psutil pywin32 Pillow --quiet
echo Starting WinDiag Pro...
python windiag.py
pause
