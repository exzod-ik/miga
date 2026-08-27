using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MIGA_Agent.Helpers;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace MIGA_Agent.ViewModels
{
    /// <summary>
    /// Модель одной вкладки сервера: настройки перенаправления, SSH-подключение,
    /// управление серверным демоном и его конфигурацией.
    /// </summary>
    public partial class ServerTabViewModel : ObservableObject
    {
        private readonly ILocalServiceManager _localService;
        private readonly IDialogService _dialogService;
        private readonly ISshManager _sshManager;

        /// <summary>Перезапуск локальной службы с предупреждением (реализует MainViewModel).</summary>
        private readonly Func<Task<bool>> _restartLocalServiceAsync;

        /// <summary>Сохранение всего клиентского конфига (реализует MainViewModel).</summary>
        private readonly Func<Task> _persistConfigAsync;

        private const string RequiredServerVersion = "1.2.0";

        /// <summary>Вкладка просит удалить сервер (вкладку).</summary>
        public event EventHandler? RemoveRequested;

        /// <summary>Свойства, изменение которых означает несохранённые правки конфига.</summary>
        private static readonly HashSet<string> ConfigProperties = new()
        {
            nameof(ServerIp),
            nameof(ServerPortsStart),
            nameof(ServerPortsEnd),
            nameof(XorKey),
            nameof(SwapKey)
        };

        public ServerTabViewModel(
            ILocalServiceManager localService,
            IDialogService dialogService,
            ISshManager sshManager,
            Func<Task<bool>> restartLocalServiceAsync,
            Func<Task> persistConfigAsync)
        {
            _localService = localService;
            _dialogService = dialogService;
            _sshManager = sshManager;
            _restartLocalServiceAsync = restartLocalServiceAsync;
            _persistConfigAsync = persistConfigAsync;

            LogLevels = new List<string> { "none", "error", "info", "debug" };

            PropertyChanged += OnSelfPropertyChanged;
            RedirectProcesses.CollectionChanged += (_, _) => MarkDirty();
            RedirectIps.CollectionChanged += (_, _) => MarkDirty();
            RedirectDomains.CollectionChanged += (_, _) => MarkDirty();
        }

        // ========== Публичные свойства ==========

        [ObservableProperty]
        private string _serverIp = string.Empty;

        [ObservableProperty]
        private int _serverPortsStart = 10000;

        [ObservableProperty]
        private int _serverPortsEnd = 15000;

        [ObservableProperty]
        private string _xorKey = string.Empty;

        [ObservableProperty]
        private string _swapKey = string.Empty;

        // SSH
        [ObservableProperty]
        private string _serverSshUser = "root";

        [ObservableProperty]
        private string _serverSshPassword = string.Empty;

        [ObservableProperty]
        private bool _isSshConnected = false;

        [ObservableProperty]
        private string _sshButtonText = "Подключиться";

        // Демон сервера
        [ObservableProperty]
        private string _serverDemoStatus = "Неизвестно";

        [ObservableProperty]
        private bool _serverDemoInstalled = false;

        [ObservableProperty]
        private string _dynamicDemoButtonText = "Загрузить и установить";

        // Параметры конфигурации сервера
        [ObservableProperty]
        private string _serverLogLevel = "none";

        [ObservableProperty]
        private string _dnsServer = "8.8.8.8";

        [ObservableProperty]
        private bool _isBusy = false;

        public bool IsNotBusy => !IsBusy;

        partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(IsNotBusy));

        /// <summary>Есть несохранённые изменения на вкладке.</summary>
        [ObservableProperty]
        private bool _isDirty;

        private bool _suppressDirty;

        partial void OnServerIpChanged(string value) => OnPropertyChanged(nameof(DisplayName));

        private void OnSelfPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (_suppressDirty)
                return;

            if (e.PropertyName != null && ConfigProperties.Contains(e.PropertyName))
                MarkDirty();
        }

        private void MarkDirty()
        {
            if (_suppressDirty)
                return;

            IsDirty = true;
        }

        /// <summary>Сбросить признак несохранённых изменений.</summary>
        public void MarkClean() => IsDirty = false;

        /// <summary>Заголовок вкладки.</summary>
        public string DisplayName =>
            string.IsNullOrWhiteSpace(ServerIp) ? "Новый сервер" : ServerIp;

        public List<string> LogLevels { get; }

        // Коллекции перенаправления
        public ObservableCollection<RedirectItemViewModel> RedirectProcesses { get; } = new();
        public ObservableCollection<RedirectItemViewModel> RedirectIps { get; } = new();
        public ObservableCollection<RedirectItemViewModel> RedirectDomains { get; } = new();

        // ========== Загрузка / выгрузка модели ==========

        public void LoadFrom(ServerEntry entry)
        {
            _suppressDirty = true;
            try
            {
                ServerIp = entry.ServerIp;
                ServerPortsStart = entry.ServerPorts.Start;
                ServerPortsEnd = entry.ServerPorts.End;
                XorKey = entry.Encryption.XorKey;
                SwapKey = entry.Encryption.SwapKey;

                SetItems(RedirectProcesses, entry.RedirectProcesses);
                SetItems(RedirectIps, entry.RedirectIps);
                SetItems(RedirectDomains, entry.RedirectDomains);
            }
            finally
            {
                _suppressDirty = false;
            }

            MarkClean();
        }

        public ServerEntry ToServerEntry() => new()
        {
            ServerIp = ServerIp,
            ServerPorts = new PortRange { Start = ServerPortsStart, End = ServerPortsEnd },
            Encryption = new EncryptionKeys { XorKey = XorKey, SwapKey = SwapKey },
            RedirectProcesses = RedirectProcesses.Select(i => i.Value).ToList(),
            RedirectIps = RedirectIps.Select(i => i.Value).ToList(),
            RedirectDomains = RedirectDomains.Select(i => i.Value).ToList()
        };

        private static void SetItems(ObservableCollection<RedirectItemViewModel> target, IEnumerable<string> values)
        {
            target.Clear();
            foreach (var value in values)
                target.Add(new RedirectItemViewModel(value));
        }

        // ========== Команды ==========

        [RelayCommand]
        private async Task ToggleSsh() => await ToggleSshAsync();

        [RelayCommand]
        private async Task RefreshServerDemoStatus() => await UpdateServerDemoStatusAsync();

        [RelayCommand]
        private async Task DynamicDemo() => await DynamicDemoAsync();

        [RelayCommand]
        private async Task GenerateKeys() => await GenerateNewKeysAsync();

        [RelayCommand]
        private void RemoveServer() => RemoveRequested?.Invoke(this, EventArgs.Empty);

        // Работа со списками
        [RelayCommand]
        private void AddProcess() => AddItem(RedirectProcesses, "Введите имя процесса (например, chrome.exe):", "Добавление процесса");

        [RelayCommand]
        private void EditProcess(object? _) => EditItem(RedirectProcesses, "Редактирование процессов", "Введите список процессов (каждый с новой строки):");

        [RelayCommand]
        private void RemoveProcess(object? item) => RemoveItem(RedirectProcesses, item, "Удалить процесс");

        [RelayCommand]
        private void AddIp() => AddItem(RedirectIps, "Введите IP-адрес или диапазон (например, 192.168.1.1 или 192.168.1.1-192.168.3.255):", "Добавление IP");

        [RelayCommand]
        private void EditIp(object? _) => EditItem(RedirectIps, "Редактирование IP", "Введите список IP-адресов или диапазонов (каждый с новой строки):");

        [RelayCommand]
        private void RemoveIp(object? item) => RemoveItem(RedirectIps, item, "Удалить IP");

        [RelayCommand]
        private void AddDomain() => AddItem(RedirectDomains, "Введите доменное имя (например, example.com):", "Добавление домена");

        [RelayCommand]
        private void EditDomain(object? _) => EditItem(RedirectDomains, "Редактирование доменов", "Введите список доменных имён (каждый с новой строки):");

        [RelayCommand]
        private void RemoveDomain(object? item) => RemoveItem(RedirectDomains, item, "Удалить домен");

        // ========== Приватные методы ==========

        private static List<string> ParseInput(string input)
        {
            return input.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(s => s.Trim())
                        .Where(s => !string.IsNullOrEmpty(s))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
        }

        private void AddItem(ObservableCollection<RedirectItemViewModel> collection, string prompt, string title)
        {
            string? input = _dialogService.ShowMultiLineInputDialog(prompt, title, "");
            if (string.IsNullOrWhiteSpace(input))
                return;

            foreach (var value in ParseInput(input))
            {
                if (!collection.Any(i => string.Equals(i.Value, value, StringComparison.OrdinalIgnoreCase)))
                    collection.Add(new RedirectItemViewModel(value));
            }
        }

        private void EditItem(ObservableCollection<RedirectItemViewModel> collection, string title, string prompt)
        {
            string currentText = string.Join(Environment.NewLine, collection.Select(i => i.Value));
            string? input = _dialogService.ShowMultiLineInputDialog(prompt, title, currentText);
            if (string.IsNullOrWhiteSpace(input))
                return;

            SetItems(collection, ParseInput(input));
        }

        private void RemoveItem(ObservableCollection<RedirectItemViewModel> collection, object? item, string title)
        {
            if (item is not RedirectItemViewModel redirectItem)
                return;

            if (_dialogService.ShowYesNo($"Удалить {redirectItem.Value}?", title))
                collection.Remove(redirectItem);
        }

        private async Task ToggleSshAsync()
        {
            if (!IsSshConnected)
            {
                if (string.IsNullOrWhiteSpace(ServerIp))
                {
                    _dialogService.ShowWarning("Укажите Server IP");
                    return;
                }
                if (string.IsNullOrWhiteSpace(ServerSshUser))
                {
                    _dialogService.ShowWarning("Введите пользователя");
                    return;
                }
                if (string.IsNullOrWhiteSpace(ServerSshPassword))
                {
                    _dialogService.ShowWarning("Введите пароль");
                    return;
                }
                try
                {
                    await _sshManager.ConnectAsync(ServerIp, 22, ServerSshUser, ServerSshPassword);
                    IsSshConnected = true;
                    SshButtonText = "Отключить";
                    await UpdateServerDemoStatusAsync();
                    await LoadServerConfigAsync();
                }
                catch (Exception ex)
                {
                    _dialogService.ShowError($"Ошибка SSH подключения: {ex.Message}");
                }
            }
            else
            {
                try
                {
                    _sshManager.Disconnect();
                    IsSshConnected = false;
                    SshButtonText = "Подключиться";
                    ServerDemoStatus = "Неизвестно";
                    ServerDemoInstalled = false;
                    DynamicDemoButtonText = "Загрузить и установить";
                }
                catch (Exception ex)
                {
                    _dialogService.ShowError($"Ошибка отключения SSH: {ex.Message}");
                }
            }
        }

        private async Task UpdateServerDemoStatusAsync()
        {
            if (!_sshManager.IsConnected)
            {
                ServerDemoStatus = "Нет подключения";
                ServerDemoInstalled = false;
                DynamicDemoButtonText = "Загрузить и установить";
                return;
            }

            try
            {
                string statusOutput = await _sshManager.ExecuteCommandAsync("systemctl status miga_server 2>&1 || true");
                if (statusOutput.Contains("not found") || statusOutput.Contains("No such file") || statusOutput.Contains("could not be found"))
                {
                    ServerDemoInstalled = false;
                    ServerDemoStatus = "Не установлен";
                    DynamicDemoButtonText = "Загрузить и установить";
                    return;
                }

                string versionOutput = await _sshManager.ExecuteCommandAsync("/usr/local/miga_server --version 2>&1 || true");
                string actualVersion = versionOutput.Trim().Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                var versionMatch = System.Text.RegularExpressions.Regex.Match(actualVersion, @"(\d+\.\d+\.\d+)");
                string versionNumber = versionMatch.Success ? versionMatch.Groups[1].Value : actualVersion;

                if (versionNumber != RequiredServerVersion)
                {
                    ServerDemoInstalled = true;
                    ServerDemoStatus = "Устаревшая версия";
                    DynamicDemoButtonText = "Обновить сервер";
                    return;
                }

                ServerDemoInstalled = true;
                string result = await _sshManager.ExecuteCommandAsync("systemctl is-active miga_server");
                bool isActive = result.Trim() == "active";
                ServerDemoStatus = isActive ? "Работает" : "Остановлен";
                DynamicDemoButtonText = isActive ? "Остановить" : "Запустить";
            }
            catch
            {
                ServerDemoStatus = "Ошибка";
                ServerDemoInstalled = false;
                DynamicDemoButtonText = "Загрузить и установить";
            }
        }

        private async Task DynamicDemoAsync()
        {
            if (!_sshManager.IsConnected)
            {
                _dialogService.ShowWarning("Сначала установите SSH подключение");
                return;
            }

            if (!ServerDemoInstalled)
            {
                await UploadAndInstallInternalAsync();
            }
            else if (ServerDemoStatus == "Устаревшая версия")
            {
                await UpdateServerInternalAsync();
            }
            else if (ServerDemoStatus == "Остановлен")
            {
                await StartServerDemoInternalAsync();
            }
            else if (ServerDemoStatus == "Работает")
            {
                await StopServerDemoInternalAsync();
            }
        }

        private async Task UpdateServerInternalAsync()
        {
            IsBusy = true;

            var notification = _dialogService.ShowPersistent("Обновление сервера");

            try
            {
                bool wasRunning = ServerDemoStatus == "Работает";

                if (wasRunning)
                {
                    _dialogService.UpdatePersistent(notification, "Обновление сервера", "Остановка демона...");
                    await _sshManager.ExecuteCommandAsync("systemctl stop miga_server");
                    await Task.Delay(2000);
                }

                string pgrep = await _sshManager.ExecuteCommandAsync("pgrep -f miga_server || true");
                if (!string.IsNullOrWhiteSpace(pgrep))
                {
                    _dialogService.UpdatePersistent(notification, "Обновление сервера", "Принудительное завершение процесса...");
                    await _sshManager.ExecuteCommandAsync("pkill -f miga_server || true");
                    await Task.Delay(1000);
                }

                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string localMigraServer = Path.Combine(appDirectory, "miga_server");

                if (!File.Exists(localMigraServer))
                    throw new FileNotFoundException($"miga_server не найден в {appDirectory}");

                _dialogService.UpdatePersistent(notification, "Обновление сервера", "Копирование нового файла...");

                string tempRemotePath = "/usr/local/miga_server.new";
                await _sshManager.UploadFileAsync(localMigraServer, tempRemotePath);
                await _sshManager.ExecuteCommandAsync($"chmod +x {tempRemotePath}");

                _dialogService.UpdatePersistent(notification, "Обновление сервера", "Замена исполняемого файла...");
                await _sshManager.ExecuteCommandAsync($"mv {tempRemotePath} /usr/local/miga_server");

                _dialogService.UpdatePersistent(notification, "Обновление сервера", "Обновляем конфигурацию...");
                await _sshManager.ExecuteCommandAsync("/usr/local/miga_server --update");

                if (wasRunning)
                {
                    _dialogService.UpdatePersistent(notification, "Обновление сервера", "Запуск демона...");
                    await _sshManager.ExecuteCommandAsync("systemctl start miga_server");
                    await Task.Delay(1000);
                }

                await UpdateServerDemoStatusAsync();

                _dialogService.ClosePersistent(notification, "Обновление сервера", "Сервер успешно обновлён");
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка обновления", $"Ошибка: {ex.Message}");
                _dialogService.ShowError($"Ошибка обновления сервера: {ex.Message}");
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task UploadAndInstallInternalAsync()
        {
            IsBusy = true;

            var notification = _dialogService.ShowPersistent("Установка сервера");

            try
            {
                string appDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string localMigraServer = Path.Combine(appDirectory, "miga_server");
                string localInstallScript = Path.Combine(appDirectory, "install.sh");

                if (!File.Exists(localMigraServer))
                    throw new FileNotFoundException($"miga_server не найден в {appDirectory}");
                if (!File.Exists(localInstallScript))
                    throw new FileNotFoundException($"install.sh не найден в {appDirectory}");

                _dialogService.UpdatePersistent(notification, "Установка сервера", "Копирование файлов...");
                await _sshManager.ExecuteCommandAsync("mkdir -p /tmp/miga_install");
                await _sshManager.UploadFileAsync(localMigraServer, "/usr/local/miga_server");
                await _sshManager.ExecuteCommandAsync("chmod +x /usr/local/miga_server");

                _dialogService.UpdatePersistent(notification, "Установка сервера", "Установка...");
                string remoteScriptPath = "/tmp/miga_install/install.sh";
                await _sshManager.UploadFileAsync(localInstallScript, remoteScriptPath);
                await _sshManager.ExecuteCommandAsync($"chmod +x {remoteScriptPath}");
                string result = await _sshManager.ExecuteCommandAsync($"cd /tmp/miga_install && ./install.sh");
                await _sshManager.ExecuteCommandAsync($"rm -f {remoteScriptPath}");

                _dialogService.ClosePersistent(notification, "Установка сервера", "Установка завершена успешно");

                // Обновляем ключи с сервера
                await LoadServerConfigAsync();

                await UpdateServerDemoStatusAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка установки", $"Ошибка: {ex.Message}");
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task StartServerDemoInternalAsync()
        {
            try
            {
                await _sshManager.ExecuteCommandAsync("systemctl start miga_server");
                await UpdateServerDemoStatusAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка запуска демона: {ex.Message}");
            }
        }

        private async Task StopServerDemoInternalAsync()
        {
            try
            {
                await _sshManager.ExecuteCommandAsync("systemctl stop miga_server");
                await UpdateServerDemoStatusAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка остановки демона: {ex.Message}");
            }
        }

        private async Task GenerateNewKeysAsync()
        {
            if (!_sshManager.IsConnected)
            {
                _dialogService.ShowWarning("Для генерации ключей необходимо SSH-подключение к серверу.");
                return;
            }

            var notification = _dialogService.ShowPersistent("Генерация ключей");
            try
            {
                _dialogService.UpdatePersistent(notification, "Генерация ключей", "Выполняется miga_server --generate-keys...");
                await _sshManager.ExecuteCommandAsync("/usr/local/miga_server --generate-keys");

                _dialogService.UpdatePersistent(notification, "Генерация ключей", "Перезапуск серверного демона...");
                await _sshManager.ExecuteCommandAsync("systemctl restart miga_server");
                await Task.Delay(2000);

                _dialogService.UpdatePersistent(notification, "Генерация ключей", "Загрузка новых ключей с сервера...");
                await LoadServerConfigInternalAsync(showSyncInfo: false);

                await _persistConfigAsync();

                _dialogService.ClosePersistent(notification, "Генерация ключей", "Ключи успешно сгенерированы и синхронизированы.");

                // Предлагаем перезапустить локальную службу
                await _restartLocalServiceAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка генерации ключей", ex.Message);
                _dialogService.ShowError($"Ошибка: {ex.Message}");
            }
        }

        /// <summary>
        /// Загружает конфигурацию с удалённого сервера и синхронизирует локальные настройки.
        /// Вызывается при установке SSH-соединения.
        /// </summary>
        private async Task LoadServerConfigAsync()
        {
            await LoadServerConfigInternalAsync(showSyncInfo: true);
        }

        private async Task LoadServerConfigInternalAsync(bool showSyncInfo)
        {
            try
            {
                // Проверяем существование файла
                string checkResult = await _sshManager.ExecuteCommandAsync("test -f /etc/miga/config.json && echo 'exists' || echo 'not found'");
                if (checkResult.Trim() != "exists")
                {
                    _dialogService.ShowInfo("Конфигурация сервера не найдена. Будут использованы локальные настройки.");
                    return;
                }

                // Читаем файл
                string json = await _sshManager.ExecuteCommandAsync("cat /etc/miga/config.json");
                var serverConfig = JsonSerializer.Deserialize<ServerConfig>(json);
                if (serverConfig == null)
                {
                    _dialogService.ShowWarning("Не удалось прочитать конфигурацию сервера.");
                    return;
                }

                ServerLogLevel = serverConfig.LogLevel;
                DnsServer = serverConfig.DnsServer;

                // Обновляем локальные свойства
                if (false
                    || ServerPortsStart != serverConfig.ClientPorts.Start
                    || ServerPortsEnd != serverConfig.ClientPorts.End
                    || XorKey != serverConfig.Encryption.XorKey
                    || SwapKey != serverConfig.Encryption.SwapKey)
                {
                    ServerPortsStart = serverConfig.ClientPorts.Start;
                    ServerPortsEnd = serverConfig.ClientPorts.End;
                    XorKey = serverConfig.Encryption.XorKey;
                    SwapKey = serverConfig.Encryption.SwapKey;

                    // Сохраняем синхронизированные настройки в локальный config.json
                    await _persistConfigAsync();

                    if (showSyncInfo)
                    {
                        await _restartLocalServiceAsync();
                        _dialogService.ShowInfo("Настройки клиента синхронизированы с сервером.");
                    }
                }
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка загрузки конфигурации сервера: {ex.Message}");
            }
        }

        /// <summary>
        /// Применяет серверную часть конфигурации по SSH, если вкладка подключена.
        /// </summary>
        public async Task ApplyServerConfigIfConnectedAsync()
        {
            if (!_sshManager.IsConnected)
                return;

            try
            {
                var serverConfig = new ServerConfig
                {
                    LogLevel = ServerLogLevel,
                    ClientPorts = new PortRange { Start = ServerPortsStart, End = ServerPortsEnd },
                    Encryption = new EncryptionKeys { XorKey = XorKey, SwapKey = SwapKey },
                    DnsServer = DnsServer
                };

                string json = JsonSerializer.Serialize(serverConfig, JsonOptions.Default);
                string escapedJson = json.Replace("'", "'\\''");
                await _sshManager.ExecuteCommandAsync($"echo '{escapedJson}' > /etc/miga/config.json");
                await _sshManager.ExecuteCommandAsync("systemctl restart miga_server");
                await UpdateServerDemoStatusAsync();
                _dialogService.ShowInfo($"Конфигурация применена на сервере {DisplayName}, демон перезапущен.");
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка применения серверной конфигурации ({DisplayName}): {ex.Message}");
            }
        }

        /// <summary>Разрывает SSH-соединение (при закрытии вкладки или приложения).</summary>
        public void DisconnectSsh()
        {
            try
            {
                _sshManager.Disconnect();
            }
            catch
            {
                // игнорируем ошибки при разрыве соединения
            }
            IsSshConnected = false;
            SshButtonText = "Подключиться";
        }
    }
}
