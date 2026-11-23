@echo off
setlocal
cd /d "%~dp0..\.."
if not exist Build\v2-session-tests mkdir Build\v2-session-tests
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /DSODIUM_STATIC /I Shared /I dependencies\libsodium-1.0.22\src\libsodium\include /I dependencies\noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\include miga_client\tests\ProtocolV2SessionTests.cpp miga_client\src\ProtocolV2Session.cpp Shared\ProtocolV2.cpp Shared\ProtocolV2Packets.cpp Shared\InternetChecksum.cpp /FoBuild\v2-session-tests\ /FeBuild\v2-session-tests\protocol-v2-session-tests.exe /link ws2_32.lib Build\protocol-v2\lib\libsodium.lib Build\protocol-v2\lib\noiseprotocol.lib
if errorlevel 1 exit /b 1
Build\v2-session-tests\protocol-v2-session-tests.exe
exit /b %errorlevel%
