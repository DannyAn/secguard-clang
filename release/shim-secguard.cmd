@echo off
rem bin/secguard.cmd — SecGuard plugin 的 Windows 统一入口。
rem Windows 不执行 POSIX sh，因此用 cmd 直接调用 windows-amd64 二进制。
setlocal
"%~dp0secguard-windows-amd64.exe" %*
