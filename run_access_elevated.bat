@echo off
cd /d C:\dev\fortesp
echo === access (token/acl dump) ===
out\loader.exe --access
echo access_rc=%errorlevel%
echo ALL_DONE
