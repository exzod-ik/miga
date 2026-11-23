@echo off
setlocal
cd /d "%~dp0..\.."
if not exist Build\tests mkdir Build\tests
set V2INCLUDES=/DSODIUM_STATIC /I dependencies\libsodium-1.0.22\src\libsodium\include /I dependencies\noise-c-cfe25410979a87391bb9ac8d4d4bef64e9f268c6\include
set V2SOURCES=Shared\DiagnosticLoad.cpp Shared\ProtocolV2.cpp Shared\ProtocolV2Packets.cpp Shared\InternetChecksum.cpp miga_client\src\ProtocolProfiles.cpp miga_client\src\ProtocolV2Session.cpp
set V2LIBS=crypt32.lib advapi32.lib shell32.lib Build\protocol-v2\lib\libsodium.lib Build\protocol-v2\lib\noiseprotocol.lib
copy /y miga_client\windivert\x64\WinDivert.dll Build\tests\WinDivert.dll >nul
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\RuntimeStateTests.cpp miga_client\src\PacketTypes.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\runtime\FlowTable.cpp miga_client\src\runtime\RuntimeTypes.cpp miga_client\src\runtime\SocketDirectory.cpp /FoBuild\tests\ /FeBuild\tests\runtime-state-tests.exe /link ws2_32.lib
if not "%errorlevel%"=="0" exit /b 1
Build\tests\runtime-state-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\NetworkQueueTests.cpp miga_client\src\Ipv4Batch.cpp miga_client\src\PacketTypes.cpp /FoBuild\tests\ /FeBuild\tests\network-queue-tests.exe
if not "%errorlevel%"=="0" exit /b 1
Build\tests\network-queue-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\ProcessIdentityTests.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\WindowsProcessIdentity.cpp /FoBuild\tests\ /FeBuild\tests\process-identity-tests.exe
if not "%errorlevel%"=="0" exit /b 1
Build\tests\process-identity-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W3 /I miga_client\include /I Shared %V2INCLUDES% miga_client\tests\RoutingIndexTests.cpp %V2SOURCES% Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp miga_client\src\ConfigManager.cpp /FoBuild\tests\ /FeBuild\tests\routing-index-tests.exe /link ws2_32.lib %V2LIBS%
if not "%errorlevel%"=="0" exit /b 1
Build\tests\routing-index-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /O2 /MD /EHsc /std:c++20 /W3 /I miga_client\include /I Shared %V2INCLUDES% miga_client\tests\NetworkRuntimeTests.cpp %V2SOURCES% miga_client\src\DiagnosticSession.cpp Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp miga_client\src\AsyncTunnelSender.cpp miga_client\src\ConfigManager.cpp miga_client\src\Ipv4Batch.cpp miga_client\src\NetworkRuntime.cpp miga_client\src\PacketBufferPool.cpp miga_client\src\PacketTypes.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\TunnelDatagram.cpp miga_client\src\TunnelRouteCache.cpp miga_client\src\WindowsProcessIdentity.cpp miga_client\src\runtime\DnsClassifier.cpp miga_client\src\runtime\SyntheticDnsResolver.cpp miga_client\src\runtime\SyntheticDnsStore.cpp miga_client\src\runtime\SyntheticDnsWire.cpp miga_client\src\runtime\FlowTable.cpp miga_client\src\runtime\RuntimeConfig.cpp miga_client\src\runtime\RuntimeTypes.cpp miga_client\src\runtime\SocketDirectory.cpp miga_client\src\runtime\WindowsSnapshot.cpp /FoBuild\tests\ /FeBuild\tests\network-runtime-tests.exe /link %V2LIBS% advapi32.lib ws2_32.lib iphlpapi.lib miga_client\windivert\x64\WinDivert.lib
if not "%errorlevel%"=="0" exit /b 1
Build\tests\network-runtime-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++17 /W4 /WX /I miga_client\include /I Shared miga_client\tests\LoggerTests.cpp Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp /FoBuild\tests\ /FeBuild\tests\logger-tests.exe
if not "%errorlevel%"=="0" exit /b 1
Build\tests\logger-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\PacketBufferPoolTests.cpp miga_client\src\PacketBufferPool.cpp /FoBuild\tests\ /FeBuild\tests\packet-buffer-pool-tests.exe
if not "%errorlevel%"=="0" exit /b 1
Build\tests\packet-buffer-pool-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /DWINDIVERTEXPORT=extern /I miga_client\include /I Shared miga_client\tests\TunnelSendTests.cpp Shared\InternetChecksum.cpp miga_client\src\AsyncTunnelSender.cpp miga_client\src\TunnelDatagram.cpp miga_client\src\TunnelRouteCache.cpp /FoBuild\tests\ /FeBuild\tests\tunnel-send-tests.exe /link ws2_32.lib iphlpapi.lib
if not "%errorlevel%"=="0" exit /b 1
Build\tests\tunnel-send-tests.exe
if not "%errorlevel%"=="0" exit /b 1
cl /nologo /MD /EHsc /std:c++20 /W4 /WX /I miga_client\include miga_client\tests\SyntheticDnsTests.cpp miga_client\src\runtime\SyntheticDnsStore.cpp miga_client\src\runtime\SyntheticDnsWire.cpp /FoBuild\tests\ /FeBuild\tests\synthetic-dns-tests.exe /link advapi32.lib
if not "%errorlevel%"=="0" exit /b 1
Build\tests\synthetic-dns-tests.exe
if not "%errorlevel%"=="0" exit /b 1
exit /b 0
