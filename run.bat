@echo off
rem Email Header Analyzer - Desktop launcher
python "%~dp0main.py" %*
if errorlevel 1 pause