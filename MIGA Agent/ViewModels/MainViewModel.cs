using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
using Notification.Wpf;
using Notification.Wpf.Controls;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace MIGA_Agent.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly ILocalServiceManager _localService;
        private readonly IClientConfigService _configService;
        private readonly ISshManager _sshManager;
        private readonly IDialogService _dialogService;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        public MainViewModel(
            ILocalServiceManager localService,
            IClientConfigService configService,
            ISshManager sshManager,
            IDialogService dialogService)
        {
            _localService = localService;
            _configService = configService;
            _sshManager = sshManager;
            _dialogService = dialogService;

            RedirectProcesses = new ObservableCollection<string>();
            RedirectIps = new ObservableCollection<string>();
            LogLevels = new List<string> { "none", "error", "info", "debug" };

            Application.Current.Dispatcher.InvokeAsync(async () => await LoadInitialDataAsync());
        }

        // ========== Публичные свойства ==========

        [ObservableProperty]
        private string _serverIp = "127.0.0.1";

        [ObservableProperty]
        private int _serverPortsStart = 10000;

        [ObservableProperty]
        private int _serverPortsEnd = 15000;

        [ObservableProperty]
        private string _logLevel = "none";

        [ObservableProperty]
        private string _xorKey = string.Empty;

        [ObservableProperty]
        private string _swapKey = string.Empty;

        [ObservableProperty]
        private string _serviceStatus = "Неизвестно";

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
        private bool _isBusy = false;

        // Вспомогательное свойство для привязки (можно использовать конвертер, но так проще)
        public bool IsNotBusy => !IsBusy;

        // Коллекции
        public ObservableCollection<string> RedirectProcesses { get; }
        public ObservableCollection<string> RedirectIps { get; }
        public List<string> LogLevels { get; }

        // ========== Команды ==========

        [RelayCommand]
        private async Task RefreshServiceStatus() => await UpdateServiceStatusAsync();

        [RelayCommand(CanExecute = nameof(CanStartLocalService))]
        private async Task StartLocalService() => await StartLocalServiceAsync();
        private bool CanStartLocalService() => ServiceStatus == "Остановлена";

        [RelayCommand(CanExecute = nameof(CanStopLocalService))]
        private async Task StopLocalService() => await StopLocalServiceAsync();
        private bool CanStopLocalService() => ServiceStatus == "Работает";

        [RelayCommand]
        private async Task ToggleSsh() => await ToggleSshAsync();

        [RelayCommand]
        private async Task RefreshServerDemoStatus() => await UpdateServerDemoStatusAsync();

        [RelayCommand]
        private async Task DynamicDemo() => await DynamicDemoAsync();

        [RelayCommand]
        private async Task ApplyConfiguration() => await ApplyConfigurationAsync();

        [RelayCommand]
        private void GenerateKeys() => GenerateNewKeys();

        [RelayCommand]
        private async Task SaveRedirectsOnly() => await SaveRedirectsOnlyAsync();

        // Работа со списками
        [RelayCommand]
        private void AddProcess() => AddItem(RedirectProcesses, "Введите имя процесса (например, chrome.exe):", "Добавление процесса");

        [RelayCommand]
        private void EditProcess(object? processName) => EditItem(RedirectProcesses, processName as string, "Редактирование процесса", "Введите новое имя процесса:");

        [RelayCommand]
        private void RemoveProcess(object? processName) => RemoveItem(RedirectProcesses, processName as string, "Удалить процесс");

        [RelayCommand]
        private void AddIp() => AddItem(RedirectIps, "Введите IP-адрес или диапазон (например, 192.168.1.1 или 192.168.1.1-192.168.3.255):", "Добавление IP");

        [RelayCommand]
        private void EditIp(object? ip) => EditItem(RedirectIps, ip as string, "Редактирование IP", "Введите новый IP-адрес или диапазон:");

        [RelayCommand]
        private void RemoveIp(object? ip) => RemoveItem(RedirectIps, ip as string, "Удалить IP");

        // ========== Приватные методы ==========

        private async Task LoadInitialDataAsync()
        {
            try
            {
                await LoadClientConfigAsync();
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("не установлена"))
            {
                _dialogService.ShowError(ex.Message);
                Application.Current.Shutdown();
                return;
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка инициализации: {ex.Message}");
                Application.Current.Shutdown();
                return;
            }
            await UpdateServiceStatusAsync();
        }

        private async Task LoadClientConfigAsync()
        {
            var config = await _configService.LoadAsync();
            ServerIp = config.ServerIp;
            ServerPortsStart = config.ServerPorts.Start;
            ServerPortsEnd = config.ServerPorts.End;
            LogLevel = config.LogLevel;
            XorKey = config.Encryption.XorKey;
            SwapKey = config.Encryption.SwapKey;

            RedirectProcesses.Clear();
            foreach (var proc in config.RedirectProcesses)
                RedirectProcesses.Add(proc);

            RedirectIps.Clear();
            foreach (var ip in config.RedirectIps)
                RedirectIps.Add(ip);
        }

        private async Task SaveClientConfigAsync()
        {
            var config = new ClientConfig
            {
                ServerIp = ServerIp,
                ServerPorts = new PortRange { Start = ServerPortsStart, End = ServerPortsEnd },
                LogLevel = LogLevel,
                Encryption = new EncryptionKeys { XorKey = XorKey, SwapKey = SwapKey },
                RedirectProcesses = RedirectProcesses.ToList(),
                RedirectIps = RedirectIps.ToList()
            };
            string json = JsonSerializer.Serialize(config, JsonOptions);
            await File.WriteAllTextAsync(_configService.ConfigFilePath, json);
        }

        private async Task SaveRedirectsOnlyAsync()
        {
            var config = await _configService.LoadAsync();
            config.RedirectProcesses = RedirectProcesses.ToList();
            config.RedirectIps = RedirectIps.ToList();
            await _configService.SaveAsync(config);

            _localService.ReloadConfig();
            _dialogService.ShowInfo("Изменения сохранены");
        }

        private async Task GenerateNewKeys()
        {
            if (!IsSshConnected)
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
                await LoadServerConfigAsync(); // обновит локальные ключи и порты

                await SaveClientConfigAsync();

                _dialogService.ClosePersistent(notification, "Генерация ключей", "Ключи успешно сгенерированы и синхронизированы.");

                // Предлагаем перезапустить локальную службу
                await RestartLocalServiceWithWarningAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка генерации ключей", ex.Message);
                _dialogService.ShowError($"Ошибка: {ex.Message}");
            }
        }

        private async Task UpdateServiceStatusAsync()
        {
            try
            {
                var status = _localService.GetStatus();
                ServiceStatus = status switch
                {
                    System.ServiceProcess.ServiceControllerStatus.Running => "Работает",
                    System.ServiceProcess.ServiceControllerStatus.Stopped => "Остановлена",
                    System.ServiceProcess.ServiceControllerStatus.StartPending => "Запускается...",
                    System.ServiceProcess.ServiceControllerStatus.StopPending => "Останавливается...",
                    _ => "Неизвестно или служба не найдена"
                };
            }
            catch (Exception ex)
            {
                ServiceStatus = "Ошибка";
                _dialogService.ShowError($"Не удалось получить статус службы: {ex.Message}");
            }

            // Обновляем состояние кнопок "Запустить"/"Остановить"
            (StartLocalServiceCommand as IAsyncRelayCommand)?.NotifyCanExecuteChanged();
            (StopLocalServiceCommand as IAsyncRelayCommand)?.NotifyCanExecuteChanged();
        }

        private async Task StartLocalServiceAsync()
        {
            try
            {
                _localService.Start();
                await UpdateServiceStatusAsync();
                _dialogService.ShowInfo("Служба запущена");
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка запуска службы: {ex.Message}");
            }
        }

        private async Task StopLocalServiceAsync()
        {
            try
            {
                _localService.Stop();
                await UpdateServiceStatusAsync();
                _dialogService.ShowInfo("Служба остановлена");
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка остановки службы: {ex.Message}");
            }
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
            if (!IsSshConnected)
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
            if (!IsSshConnected)
            {
                _dialogService.ShowWarning("Сначала установите SSH подключение");
                return;
            }

            if (!ServerDemoInstalled)
            {
                await UploadAndInstallInternalAsync();
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

        private async Task UploadAndInstallInternalAsync()
        {
            IsBusy = true;
            OnPropertyChanged(nameof(IsNotBusy));

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
                OnPropertyChanged(nameof(IsNotBusy));
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

        private async Task ApplyConfigurationAsync()
        {
            await SaveClientConfigAsync();

            if (IsSshConnected)
            {
                await ApplyServerConfigInternalAsync();
            }
            else
            {
                _dialogService.ShowInfo("Конфигурация клиента сохранена. Для применения на сервере установите SSH-подключение.");
            }

            // Предлагаем перезапустить локальную службу
            await RestartLocalServiceWithWarningAsync();
        }

        private async Task LoadServerConfigAsync()
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
                var serverConfig = System.Text.Json.JsonSerializer.Deserialize<ServerConfig>(json);
                if (serverConfig == null)
                {
                    _dialogService.ShowWarning("Не удалось прочитать конфигурацию сервера.");
                    return;
                }

                // Обновляем локальные свойства
                if (false
                    || ServerLogLevel != serverConfig.LogLevel
                    || ServerPortsStart != serverConfig.ClientPorts.Start
                    || ServerPortsEnd != serverConfig.ClientPorts.End
                    || XorKey != serverConfig.Encryption.XorKey
                    || SwapKey != serverConfig.Encryption.SwapKey)
                {
                    ServerLogLevel = serverConfig.LogLevel;
                    ServerPortsStart = serverConfig.ClientPorts.Start;
                    ServerPortsEnd = serverConfig.ClientPorts.End;
                    XorKey = serverConfig.Encryption.XorKey;
                    SwapKey = serverConfig.Encryption.SwapKey;

                    // Сохраняем синхронизированные настройки в локальный config.json
                    await SaveClientConfigAsync();
                    await RestartLocalServiceWithWarningAsync();
                    _dialogService.ShowInfo("Настройки клиента синхронизированы с сервером.");
                }
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка загрузки конфигурации сервера: {ex.Message}");
            }
        }

        private async Task ApplyServerConfigInternalAsync()
        {
            try
            {
                var serverConfig = new ServerConfig
                {
                    LogLevel = ServerLogLevel,
                    ClientPorts = new PortRange { Start = ServerPortsStart, End = ServerPortsEnd },
                    Encryption = new EncryptionKeys { XorKey = XorKey, SwapKey = SwapKey }
                };

                string json = JsonSerializer.Serialize(serverConfig, JsonOptions);
                string escapedJson = json.Replace("'", "'\\''");
                await _sshManager.ExecuteCommandAsync($"echo '{escapedJson}' > /etc/miga/config.json");
                await _sshManager.ExecuteCommandAsync("systemctl restart miga_server");
                await UpdateServerDemoStatusAsync();
                _dialogService.ShowInfo("Конфигурация клиента сохранена, серверная конфигурация применена, демон перезапущен.");
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка применения серверной конфигурации: {ex.Message}");
            }
        }
        private void AddItem(ObservableCollection<string> collection, string prompt, string title)
        {
            string? newItem = _dialogService.ShowInputDialog(prompt, title);
            if (!string.IsNullOrWhiteSpace(newItem) && !collection.Contains(newItem))
                collection.Add(newItem);
        }

        private void EditItem(ObservableCollection<string> collection, string? oldValue, string title, string prompt)
        {
            if (oldValue == null) return;
            string? newValue = _dialogService.ShowInputDialog(prompt, title, oldValue);
            if (!string.IsNullOrWhiteSpace(newValue) && newValue != oldValue)
            {
                int index = collection.IndexOf(oldValue);
                if (index != -1)
                    collection[index] = newValue;
            }
        }

        private void RemoveItem(ObservableCollection<string> collection, string? item, string title)
        {
            if (item == null) return;
            if (_dialogService.ShowYesNo($"Удалить {item}?", title))
                collection.Remove(item);
        }

        private async Task<bool> RestartLocalServiceWithWarningAsync()
        {
            var status = _localService.GetStatus();
            if (status != System.ServiceProcess.ServiceControllerStatus.Running)
            {
                return false;
            }

            if (!_dialogService.ShowYesNo(
                "Применение изменений потребует перезапуска локальной службы MigaClient.\n\n" +
                "Все активные соединения будут сброшены. Продолжить?",
                "Подтверждение перезапуска"))
            {
                return false;
            }

            try
            {
                _dialogService.ShowInfo("Перезапуск локальной службы...");
                _localService.Stop();
                await Task.Delay(2000); // Даём время корректно остановиться
                _localService.Start();
                await UpdateServiceStatusAsync();
                _dialogService.ShowInfo("Локальная служба успешно перезапущена.");
                return true;
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка при перезапуске службы: {ex.Message}");
                return false;
            }
        }
    }
}