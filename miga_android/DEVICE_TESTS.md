# Проверки на Android-устройстве

USB-подключение проверено 2026-11-14: TECNO CM7, Android 16 / API 36, arm64-v8a, страницы 4096 байт. ADB показывает состояние device. Уже установлена org.miga.android версии 1.0.1 (versionCode 2); установленные данные и приложение не изменялись.

## Подготовленные проверки

Тестовый APK собирается на компьютере командой `gradlew.bat :devicechecks:assembleDebug --offline`. Артефакт: ../Build/android/devicechecks/outputs/apk/debug/devicechecks-debug.apk. Пакет org.miga.android.devicechecks содержит собственный код, JNI и instrumentation, нацеленный только на себя; разрешение INTERNET нужно для локальных сокетов. Основная org.miga.android не запускается и не обновляется.

На TECNO длительный тестовый процесс без Activity попадал в do_freezer_trap; флаг Android isFrozen при этом оставался false. Отдельный пакет теперь открывает CheckActivity на время теста и держит экран включённым только пока это окно видно. Глобальные настройки питания не меняются.

Режим `direct` использует те же три исходных класса из core/src/test/kotlin, что JVM-прогон Windows, всего 13 тестов. Gradle копирует выбранные исходники в ../Build/.work/<run>/devicechecks/generated/checks; править копии не следует. Режим не открывает VPS, не поднимает VPN и использует только loopback телефона:

- TCP: двусторонняя передача, активная загрузка/отдача дольше idle-тайм-аута, продолжение загрузки после shutdownOutput, завершение полностью неактивного соединения.
- Зависшая запись: истечение idle-тайм-аута при половинном закрытии и при двух заблокированных направлениях, освобождение единственного слота, завершение потоков при Stop.
- UDP: SOCKS5 UDP ASSOCIATE, запрос и ответ через несоединённый сокет, закрытие ассоциации.
- Ограничения: лимит сессий, завершение активных и ожидающих соединений, отказ новых подключений после Stop.

Режим `native` отдельно проверяет загрузку HEV и miga-v2 JNI. Он не доказывает работу VPN или настоящего туннеля.

## Запуск отдельного пакета

Для instrument требуется только установленный пакет org.miga.android.devicechecks. Его установка и запуск разрешены отдельно. Существующая MIGA не должна удаляться, обновляться, переподписываться или очищаться.

Команды для самостоятельного прогона установленного тестового пакета:

```powershell
adb -d shell am instrument -w -r -e suite direct org.miga.android.devicechecks/org.miga.android.NativeLoadInstrumentation
adb -d shell am instrument -w -r -e suite native org.miga.android.devicechecks/org.miga.android.NativeLoadInstrumentation
```

Для direct ожидаются tests=13, failures=0, ignored=0 и INSTRUMENTATION_CODE=-1. Для native ожидаются nativeLoad=ok и INSTRUMENTATION_CODE=-1. Ошибки JUnit возвращаются в details со стеком. Сохранить весь вывод, а не только код процесса adb. Если выполнение прервано, итог отсутствует или тестов меньше 13, прогон не считать успешным. Windows-службы и AdGuard для этих проверок останавливать не требуется.

## Следующий этап

После отдельных разрешений на установку и запуск VPN: проверить DIRECT через настоящие TUN/HEV и защищённые сокеты, затем TCP/UDP через совместимый сервер v2, смену Wi-Fi/мобильной сети, Stop/повторный старт и работу при выключенном экране. Для каждого сценария зафиксировать направление, счётчики и фактический ответ. Сейчас эти проверки только запланированы; VPS и настройки телефона не менялись.

## Результат 2026-11-14

На TECNO CM7 / Android 16 общий прогон direct завершился: tests=13, failures=0, ignored=0, elapsedMillis=13071, INSTRUMENTATION_CODE=-1. Отдельные запуски каждого из 13 тестов также прошли. JNI: nativeLoad=ok, INSTRUMENTATION_CODE=-1. Отчёты: Artifacts/previous-builds/android-v2/phone-direct-foreground.txt, phone-jni-results.txt и phone-individual/results.json.

Установлен только org.miga.android.devicechecks. Метаданные кода, UID, версии и времени установки org.miga.android до и после совпадают; её настройки не читались и не изменялись. Обработка DIRECT/SOCKS и ожидания тестов не менялись. Это подтверждает проверенные сценарии на устройстве, но не объясняет точную причину сбоев loopback на Windows и не проверяет полный путь TUN/HEV или соединение с VPS.
