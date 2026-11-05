@echo off
setlocal
cd /d "%~dp0..\.."
if not exist Build\tests mkdir Build\tests
copy /y miga_client\windivert\x64\WinDivert.dll Build\tests\WinDivert.dll >nul
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\RuntimeStateTests.cpp miga_client\src\PacketTypes.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\runtime\FlowTable.cpp miga_client\src\runtime\RuntimeTypes.cpp miga_client\src\runtime\SocketDirectory.cpp /FoBuild\tests\ /FeBuild\tests\runtime-state-tests.exe /link ws2_32.lib
if errorlevel 1 exit /b 1
Build\tests\runtime-state-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\NetworkQueueTests.cpp miga_client\src\Ipv4Batch.cpp miga_client\src\PacketTypes.cpp /FoBuild\tests\ /FeBuild\tests\network-queue-tests.exe
if errorlevel 1 exit /b 1
Build\tests\network-queue-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\ProcessIdentityTests.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\WindowsProcessIdentity.cpp /FoBuild\tests\ /FeBuild\tests\process-identity-tests.exe
if errorlevel 1 exit /b 1
Build\tests\process-identity-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W3 /I miga_client\include /I Shared miga_client\tests\RoutingIndexTests.cpp Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp miga_client\src\ConfigManager.cpp /FoBuild\tests\ /FeBuild\tests\routing-index-tests.exe /link ws2_32.lib
if errorlevel 1 exit /b 1
Build\tests\routing-index-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W3 /I miga_client\include /I Shared miga_client\tests\NetworkRuntimeTests.cpp Shared\Encryption.cpp Shared\InternetChecksum.cpp Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp miga_client\src\AsyncTunnelSender.cpp miga_client\src\ConfigManager.cpp miga_client\src\Ipv4Batch.cpp miga_client\src\NetworkRuntime.cpp miga_client\src\PacketBufferPool.cpp miga_client\src\PacketTypes.cpp miga_client\src\ProcessIdentityCache.cpp miga_client\src\TunnelDatagram.cpp miga_client\src\TunnelRouteCache.cpp miga_client\src\WindowsProcessIdentity.cpp miga_client\src\runtime\DnsClassifier.cpp miga_client\src\runtime\FlowTable.cpp miga_client\src\runtime\RuntimeConfig.cpp miga_client\src\runtime\RuntimeTypes.cpp miga_client\src\runtime\SocketDirectory.cpp miga_client\src\runtime\WindowsSnapshot.cpp /FoBuild\tests\ /FeBuild\tests\network-runtime-tests.exe /link ws2_32.lib iphlpapi.lib miga_client\windivert\x64\WinDivert.lib
if errorlevel 1 exit /b 1
Build\tests\network-runtime-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++17 /W4 /WX /I miga_client\include /I Shared miga_client\tests\LoggerTests.cpp Shared\LogFormat.cpp Shared\LogTime.cpp Shared\Logger.cpp /FoBuild\tests\ /FeBuild\tests\logger-tests.exe
if errorlevel 1 exit /b 1
Build\tests\logger-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W4 /WX /I miga_client\include /I Shared miga_client\tests\PacketBufferPoolTests.cpp miga_client\src\PacketBufferPool.cpp /FoBuild\tests\ /FeBuild\tests\packet-buffer-pool-tests.exe
if errorlevel 1 exit /b 1
Build\tests\packet-buffer-pool-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++20 /W4 /WX /DWINDIVERTEXPORT=extern /I miga_client\include /I Shared miga_client\tests\TunnelSendTests.cpp Shared\InternetChecksum.cpp miga_client\src\AsyncTunnelSender.cpp miga_client\src\TunnelDatagram.cpp miga_client\src\TunnelRouteCache.cpp /FoBuild\tests\ /FeBuild\tests\tunnel-send-tests.exe /link ws2_32.lib iphlpapi.lib
if errorlevel 1 exit /b 1
Build\tests\tunnel-send-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++17 /W4 /WX /O2 /I miga_client\include /I Shared miga_client\tests\EncryptionCompatibilityTests.cpp Shared\Encryption.cpp /FoBuild\tests\ /FeBuild\tests\encryption-compatibility-tests.exe
if errorlevel 1 exit /b 1
Build\tests\encryption-compatibility-tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /std:c++17 /W3 /I miga_client\include /I Shared miga_client\tests\FragmentExpiryTests.cpp Shared\UdpPacketAssembler.cpp /FoBuild\tests\ /FeBuild\tests\fragment-expiry-tests.exe /link ws2_32.lib
if errorlevel 1 exit /b 1
Build\tests\fragment-expiry-tests.exe
if errorlevel 1 exit /b 1
exit /b 0
