@echo off
rem dshctl - control a running DeepSeek Harness instance (see README.md)
setlocal
python "%~dp0dshctl.py" %*
