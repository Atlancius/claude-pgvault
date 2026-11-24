@echo off
rem pgvault pour Windows (cmd, PowerShell) : Python 3.8+ requis.
where py >nul 2>nul && (py -3 "%~dp0..\scripts\pgvault.py" %* & exit /b %errorlevel%)
python "%~dp0..\scripts\pgvault.py" %*
