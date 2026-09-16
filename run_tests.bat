@echo off
rem Email Header Analyzer - Desktop test launcher
python -m unittest discover -s "%~dp0tests" -v
if errorlevel 1 pause