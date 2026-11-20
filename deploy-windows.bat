@echo off
chcp 65001 >nul
title vps2vpn
cd /d "%~dp0"
rem Needs nothing extra: PowerShell, tar and ssh come with Windows 10/11.
powershell -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0deploy\deploy.ps1"
if errorlevel 1 (
  echo.
  echo  部署窗口没能打开。也可以用浏览器版：安装 Python 后运行  py -3 deploy\deploy.py
  echo  The deploy window failed to open. Alternative: install Python, then run  py -3 deploy\deploy.py
  pause
)
