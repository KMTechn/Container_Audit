@echo off
setlocal
set "CONTAINER_AUDIT_PORTABLE_ROOT=%~dp0"
"%CONTAINER_AUDIT_PORTABLE_ROOT%runtime\pythonw.exe" -I -B "%CONTAINER_AUDIT_PORTABLE_ROOT%app\main.py" %*
exit /b %ERRORLEVEL%

