@echo off
setlocal
cd /d "%~dp0..\.."
if not exist Build\profile-owner-tests mkdir Build\profile-owner-tests
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /DSODIUM_STATIC /I Shared /I miga_client\include /I dependencies\libsodium-1.0.22\src\libsodium\include /I dependencies\noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\include miga_client\tests\ProtocolProfileOwnerTests.cpp Shared\ProtocolV2.cpp /FoBuild\profile-owner-tests\ /FeBuild\profile-owner-tests\protocol-profile-owner-tests.exe /link crypt32.lib advapi32.lib shell32.lib Build\protocol-v2\lib\libsodium.lib Build\protocol-v2\lib\noiseprotocol.lib
if errorlevel 1 exit /b 1
Build\profile-owner-tests\protocol-profile-owner-tests.exe
exit /b %errorlevel%
