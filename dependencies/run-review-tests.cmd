@echo off
setlocal
cd /d "%~dp0.."
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
if not exist Build\protocol-v2\review mkdir Build\protocol-v2\review
cl /nologo /EHsc /MD /std:c++17 /W4 /WX /DSODIUM_STATIC /I Shared /I dependencies\libsodium-1.0.22\src\libsodium\include /I dependencies\noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\include Shared\tests\ProtocolV2ReviewTests.cpp Shared\ProtocolV2.cpp Shared\ProtocolV2Packets.cpp Shared\InternetChecksum.cpp /FoBuild\protocol-v2\review\ /FeBuild\protocol-v2\review\protocol-v2-review.exe /link Build\protocol-v2\lib\libsodium.lib Build\protocol-v2\lib\noiseprotocol.lib advapi32.lib
if errorlevel 1 exit /b 1
Build\protocol-v2\review\protocol-v2-review.exe
exit /b %errorlevel%
