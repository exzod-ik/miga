using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using MIGA_Agent.Helpers;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
using MIGA_Agent.Views.Dialogs;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Windows;
using System.Threading.Tasks;

namespace MIGA_Agent.ViewModels
{
    public partial class ManagedServerViewModel : ObservableObject
    {
        private readonly IDialogService _dialogService;
        private readonly ISshManager _sshManager;
        private string? connectedHost;
        private string? connectedUser;
        private ServerState serverState;
        private Task<ServerState>? serverStatusCheck;

        private enum ServerState
        {
            Unknown,
            Disconnected,
            NotInstalled,
            DifferentBuild,
            BuildCheckFailed,
            ServiceCheckFailed,
            Stopped,
            Running
        }

        [RelayCommand]
        private void ManageClients()
        {
            if (IsSshConnected && CheckConnectedIdentity()) new ProtocolV2ClientsWindow(_sshManager, InvitationHandoff.SendAsync) { Owner = Application.Current.MainWindow }.ShowDialog();
        }

        [RelayCommand]
        private void OpenDiagnostics()
        {
            if (!IsSshConnected || !CheckConnectedIdentity()) return;
            new ServerDiagnosticsWindow(_sshManager, ConnectedHost()) { Owner = Application.Current.MainWindow }.ShowDialog();
        }

        private const string InstalledServerBinary = "/usr/local/miga_server";
        private static string BundledServerBinary => Path.Combine(AppContext.BaseDirectory, "miga_server");

        private static readonly HashSet<string> ConfigProperties = new()
        {
            nameof(ServerIp),
            nameof(ConnectionName),
            nameof(ServerSshUser),

        };

        public ManagedServerViewModel(IDialogService dialogService, ISshManager sshManager)
        {
            _dialogService = dialogService;
            _sshManager = sshManager;
            LogLevels = new List<string> { "none", "error", "warning", "info", "debug" };

            PropertyChanged += OnSelfPropertyChanged;
        }

        [ObservableProperty]
        private string _connectionName = string.Empty;



        partial void OnConnectionNameChanged(string value) => OnPropertyChanged(nameof(DisplayName));

        [ObservableProperty]
        private string _serverIp = string.Empty;

        [ObservableProperty]
        private string _serverSshUser = "root";

        [ObservableProperty]
        private string _serverSshPassword = string.Empty;

        [ObservableProperty]
        private bool _isSshConnected = false;

        [ObservableProperty]
        private string _sshButtonText = "Подключиться";
        [ObservableProperty]
        private string _serverDemoStatus = "Неизвестно";

        [ObservableProperty]
        private string _dynamicDemoButtonText = "Загрузить и установить";
        [ObservableProperty]
        private string _serverLogLevel = "none";

        [ObservableProperty]
        private string _dnsServer = "8.8.8.8";

        [ObservableProperty]
        private bool _isBusy = false;

        public bool IsNotBusy => !IsBusy && serverStatusCheck is null;

        partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(IsNotBusy));
        [ObservableProperty]
        private bool _isDirty;


        partial void OnServerIpChanged(string value) => OnPropertyChanged(nameof(DisplayName));

        private void OnSelfPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != null && ConfigProperties.Contains(e.PropertyName))
                MarkDirty();
        }

        private void MarkDirty()
        {
            IsDirty = true;
        }
        public void MarkClean() => IsDirty = false;
        public string DisplayName =>
            string.IsNullOrWhiteSpace(ConnectionName) ? (string.IsNullOrWhiteSpace(ServerIp) ? "Новый сервер" : ServerIp) : ConnectionName;

        public List<string> LogLevels { get; }

        [RelayCommand]
        private async Task ToggleSsh() => await ToggleSshAsync();

        [RelayCommand]
        private async Task RefreshServerDemoStatus() => await UpdateServerDemoStatusAsync();

        [RelayCommand]
        private async Task DynamicDemo() => await DynamicDemoAsync();

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
                    string host = ServerIp;
                    string user = ServerSshUser;
                    await _sshManager.ConnectAsync(host, 22, user, ServerSshPassword);
                    connectedHost = host;
                    connectedUser = user;
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
                    SetServerState(ServerState.Unknown);
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
                SetServerState(ServerState.Disconnected);
                return;
            }

            if (!CheckConnectedIdentity()) return;

            var check = ReadServerStateAsync();
            serverStatusCheck = check;
            OnPropertyChanged(nameof(IsNotBusy));
            ServerState state = await check;
            if (serverStatusCheck != check) return;

            SetServerState(state);
            serverStatusCheck = null;
            OnPropertyChanged(nameof(IsNotBusy));
        }

        private async Task<ServerState> ReadServerStateAsync()
        {
            string? activeState;
            try
            {
                string statusOutput = await _sshManager.ExecuteCheckedAsync(
                    "systemctl show --property=LoadState,ActiveState miga_server", TimeSpan.FromSeconds(15));
                string[] properties = statusOutput.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                string? loadState = properties.FirstOrDefault(line => line.StartsWith("LoadState=", StringComparison.Ordinal));
                activeState = properties.FirstOrDefault(line => line.StartsWith("ActiveState=", StringComparison.Ordinal));
                if (loadState is null or "LoadState=" || activeState is null or "ActiveState=")
                    return ServerState.ServiceCheckFailed;

                if (loadState == "LoadState=not-found" && activeState == "ActiveState=inactive")
                    return ServerState.NotInstalled;
            }
            catch
            {
                return ServerState.ServiceCheckFailed;
            }

            try
            {
                if (!await IsBundledServerInstalledAsync()) return ServerState.DifferentBuild;
            }
            catch
            {
                return ServerState.BuildCheckFailed;
            }

            return activeState == "ActiveState=active" ? ServerState.Running : ServerState.Stopped;
        }

        private async Task<bool> IsBundledServerInstalledAsync()
        {
            using var stream = File.OpenRead(BundledServerBinary);
            string bundledHash = Convert.ToHexString(await SHA256.HashDataAsync(stream));
            string output = (await _sshManager.ExecuteCheckedAsync(
                $"test -f {InstalledServerBinary} && sha256sum -- {InstalledServerBinary}", TimeSpan.FromSeconds(15))).TrimEnd();
            string expectedSuffix = "  " + InstalledServerBinary;
            if (output.Length != bundledHash.Length + expectedSuffix.Length ||
                !output.EndsWith(expectedSuffix, StringComparison.Ordinal))
                throw new InvalidDataException("Некорректный ответ sha256sum.");

            string installedHash = output[..bundledHash.Length];
            if (!installedHash.All(char.IsAsciiHexDigit))
                throw new InvalidDataException("Некорректный ответ sha256sum.");

            return string.Equals(bundledHash, installedHash, StringComparison.OrdinalIgnoreCase);
        }

        private void SetServerState(ServerState state)
        {
            serverState = state;
            (ServerDemoStatus, DynamicDemoButtonText) = state switch
            {
                ServerState.Disconnected => ("Нет подключения", "Загрузить и установить"),
                ServerState.NotInstalled => ("Не установлен", "Загрузить и установить"),
                ServerState.DifferentBuild => ("Установленная сборка отличается", "Установить сборку из комплекта"),
                ServerState.BuildCheckFailed => ("Не удалось проверить сборку", "Повторить проверку"),
                ServerState.ServiceCheckFailed => ("Не удалось проверить службу", "Повторить проверку"),
                ServerState.Stopped => ("Остановлен", "Запустить"),
                ServerState.Running => ("Работает", "Остановить"),
                _ => ("Неизвестно", "Загрузить и установить")
            };
        }

        private async Task DynamicDemoAsync()
        {
            if (!IsNotBusy) return;
            if (!_sshManager.IsConnected)
            {
                _dialogService.ShowWarning("Сначала установите SSH подключение");
                return;
            }

            if (!CheckConnectedIdentity()) return;

            switch (serverState)
            {
                case ServerState.NotInstalled:
                    await UploadAndInstallProtocolV2InternalAsync();
                    break;
                case ServerState.DifferentBuild:
                    await UpdateServerInternalAsync();
                    break;
                case ServerState.Stopped:
                    await StartServerDemoInternalAsync();
                    break;
                case ServerState.Running:
                    await StopServerDemoInternalAsync();
                    break;
                default:
                    await UpdateServerDemoStatusAsync();
                    break;
            }
        }

        private bool CheckConnectedIdentity()
        {
            if (_sshManager.IsConnected && connectedHost == ServerIp && connectedUser == ServerSshUser) return true;
            _dialogService.ShowWarning("Переподключите SSH к выбранному серверу и пользователю.");
            return false;
        }

        private string ConnectedHost()
        {
            if (!_sshManager.IsConnected || connectedHost != ServerIp || connectedUser != ServerSshUser)
                throw new InvalidOperationException("Переподключите SSH к выбранному серверу.");
            return connectedHost;
        }

        private async Task UploadServerBinaryAsync(string binary, string target)
        {
            using var stream = File.OpenRead(binary);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
            stream.Position = 0;
            await _sshManager.UploadFileAsync(stream, target);
            await _sshManager.ExecuteCheckedAsync(
                $"{{ echo '{hash}  {target}' | sha256sum -c -; }} || {{ echo server_binary_checksum_failed >&2; exit 1; }}; " +
                $"chmod 755 {target} && " +
                $"{{ {target} --version >/dev/null || {{ echo server_binary_execution_failed >&2; exit 1; }}; }}");
        }

        private async Task UpdateServerInternalAsync()
        {
            IsBusy = true;

            var notification = _dialogService.ShowPersistent("Обновление сервера");

            try
            {
                string host = ConnectedHost();
                string appDirectory = AppContext.BaseDirectory;
                string staging = "/usr/local/.miga-update-" + Guid.NewGuid().ToString("N");
                string[] updateFiles = { "install.sh", "install-v2.sh", "update-v2.py", "prepare-dependencies.sh", "ServerVersion.inc" };
                foreach (string script in updateFiles)
                    if (!File.Exists(Path.Combine(appDirectory, script)))
                        throw new FileNotFoundException(script + " отсутствует в установке Agent.");
                await _sshManager.ExecuteCheckedAsync($"mkdir -m 700 {staging}");
                string result;
                try
                {
                    _dialogService.UpdatePersistent(notification, "Обновление сервера", "Загрузка, резервное копирование и проверка запуска...");
                    await UploadServerBinaryAsync(BundledServerBinary, staging + "/miga_server");
                    foreach (string script in updateFiles)
                    {
                        using var stream = new MemoryStream(Encoding.UTF8.GetBytes((await File.ReadAllTextAsync(Path.Combine(appDirectory, script))).Replace("\r\n", "\n")));
                        await _sshManager.UploadFileAsync(stream, staging + "/" + script);
                    }
                    result = await _sshManager.ExecuteCheckedAsync($"cd {staging} && bash prepare-dependencies.sh && python3 update-v2.py {QuoteShell(host)}", TimeSpan.FromMinutes(15));
                }
                finally
                {
                    try
                    {
                        await _sshManager.ExecuteCheckedAsync($"rm -f {staging}/miga_server {staging}/install.sh {staging}/install-v2.sh {staging}/update-v2.py {staging}/prepare-dependencies.sh {staging}/ServerVersion.inc && rmdir {staging}");
                    }
                    catch (Exception cleanupError)
                    {
                        _dialogService.ShowError("Не удалось удалить временные файлы обновления: " + cleanupError.Message);
                    }
                }
                if (result.Contains("migration=1", StringComparison.Ordinal))
                    _dialogService.ShowInfo("Сервер переведён на новую версию протокола. Старые клиенты несовместимы: создайте новые приглашения через управление клиентами и импортируйте их на клиентах.\n" + result.Trim());
                else
                    _dialogService.ShowInfo("Резервная копия обновления сохранена.\n" + result.Trim());
                await UpdateServerDemoStatusAsync();

                _dialogService.ClosePersistent(notification, "Обновление сервера", "Сервер успешно обновлён");
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка обновления", ex.Message, isError: true);
                await UpdateServerDemoStatusAsync();
            }
            finally
            {
                IsBusy = false;
            }
        }

        private static string QuoteShell(string value)
        {
            if (value.Contains('\0')) throw new InvalidDataException();
            return "'" + value.Replace("'", "'\"'\"'") + "'";
        }

        private async Task UploadAndInstallProtocolV2InternalAsync()
        {
            string? outgoingInterface = _dialogService.ShowInputDialog("Выходной интерфейс сервера. Пустое поле включает выбор по маршруту IPv4. Для переноса старой конфигурации используйте «Установить сборку из комплекта».", "Установка MIGA");
            if (outgoingInterface is null) return;
            outgoingInterface = outgoingInterface.Trim();
            if (outgoingInterface.Length > 15 || outgoingInterface.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':')))
            {
                _dialogService.ShowError("Некорректное имя сетевого интерфейса.");
                return;
            }
            IsBusy = true;

            var notification = _dialogService.ShowPersistent("Установка сервера");

            try
            {
                string appDirectory = AppContext.BaseDirectory;
                string localInstallScript = Path.Combine(appDirectory, "install.sh");
                string localV2Script = Path.Combine(appDirectory, "install-v2.sh");
                string dependencyScript = Path.Combine(appDirectory, "prepare-dependencies.sh");
                if (!File.Exists(dependencyScript)) throw new FileNotFoundException("prepare-dependencies.sh отсутствует в установке Agent.");
                if (!File.Exists(localV2Script)) throw new FileNotFoundException("install-v2.sh отсутствует в установке Agent.");

                if (!File.Exists(BundledServerBinary))
                    throw new FileNotFoundException($"miga_server не найден в {appDirectory}");
                if (!File.Exists(localInstallScript))
                    throw new FileNotFoundException($"install.sh не найден в {appDirectory}");

                _dialogService.UpdatePersistent(notification, "Установка сервера", "Копирование файлов...");
                string host = ConnectedHost();
                string staging = "/usr/local/.miga-install-" + Guid.NewGuid().ToString("N");
                await _sshManager.ExecuteCheckedAsync($"mkdir -m 700 {staging}");
                try
                {
                    await UploadServerBinaryAsync(BundledServerBinary, staging + "/miga_server");
                    using var installStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(
                        (await File.ReadAllTextAsync(localInstallScript)).Replace("\r\n", "\n")));
                    await _sshManager.UploadFileAsync(installStream, staging + "/install.sh");
                    using var v2Stream = new MemoryStream(Encoding.UTF8.GetBytes((await File.ReadAllTextAsync(localV2Script)).Replace("\r\n", "\n")));
                    await _sshManager.UploadFileAsync(v2Stream, staging + "/install-v2.sh");
                    using var dependencyStream = new MemoryStream(Encoding.UTF8.GetBytes((await File.ReadAllTextAsync(dependencyScript)).Replace("\r\n", "\n")));
                    await _sshManager.UploadFileAsync(dependencyStream, staging + "/prepare-dependencies.sh");
                    await _sshManager.ExecuteCheckedAsync($"cd {staging} && bash install.sh --protocol-v2 {QuoteShell(host)} {QuoteShell(outgoingInterface)}", TimeSpan.FromMinutes(15));
                }
                finally
                {
                    try
                    {
                        await _sshManager.ExecuteCheckedAsync($"rm -f {staging}/miga_server {staging}/install.sh {staging}/install-v2.sh {staging}/prepare-dependencies.sh && rmdir {staging}");
                    }
                    catch (Exception cleanupError)
                    {
                        _dialogService.ShowError("Не удалось удалить временные файлы установки: " + cleanupError.Message);
                    }
                }
                _dialogService.ClosePersistent(notification, "Установка сервера", "Установка завершена успешно");

                _dialogService.ShowInfo("Сервер установлен. Создайте приглашение через управление клиентами по SSH и импортируйте его для подключения.");

                await UpdateServerDemoStatusAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ClosePersistent(notification, "Ошибка установки", ex.Message, isError: true);
                await UpdateServerDemoStatusAsync();
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
                if (!CheckConnectedIdentity()) return;
                await _sshManager.ExecuteCheckedAsync("systemctl start miga_server");
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
                if (!CheckConnectedIdentity()) return;
                await _sshManager.ExecuteCheckedAsync("systemctl stop miga_server");
                await UpdateServerDemoStatusAsync();
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка остановки демона: {ex.Message}");
            }
        }

        private async Task LoadServerConfigAsync()
        {
            if (!_sshManager.IsConnected || !CheckConnectedIdentity()) return;
            try
            {
                string json = await _sshManager.ExecuteCheckedAsync("cat /etc/miga/config.json");
                using var document = JsonDocument.Parse(json);
                if (!document.RootElement.TryGetProperty("protocol", out var protocol) || protocol.GetInt32() != 2)
                    throw new InvalidDataException("На сервере требуется MIGA.");
                var config = JsonSerializer.Deserialize<ServerConfig>(json) ?? throw new InvalidDataException();
                ServerLogLevel = config.LogLevel;
                DnsServer = config.DnsServer;
            }
            catch (Exception error) { _dialogService.ShowError($"Ошибка загрузки настроек сервера: {error.Message}"); }
        }
        [RelayCommand]
        private async Task ApplyServerSettings()
        {
            if (!_dialogService.ShowYesNo("Применить настройки сервера и перезапустить сервер?", "MIGA Admin")) return;
            await ApplyServerConfigIfConnectedAsync();
        }

        public async Task ApplyServerConfigIfConnectedAsync()
        {
            if (!_sshManager.IsConnected || !CheckConnectedIdentity())
                return;

            try
            {
                var serverConfig = new ServerConfig
                {
                    LogLevel = ServerLogLevel,
                    DnsServer = DnsServer
                };

                ServerConfigUpdate.Validate(serverConfig);

                string currentJson = await ExecuteConfigCommandAsync("if test -f /etc/miga/config.json; then cat /etc/miga/config.json; else printf '{}'; fi");
                string? json = ServerConfigUpdate.Prepare(currentJson, serverConfig);
                if (json == null)
                    return;
                string escapedJson = json.Replace("'", "'\\''");
                await ExecuteConfigCommandAsync("umask 077; tmp=$(mktemp /etc/miga/config.json.XXXXXX) || exit 1; " +
                    $"if printf '%s' '{escapedJson}' > \"$tmp\" && mv -f -- \"$tmp\" /etc/miga/config.json; " +
                    "then :; else rm -f -- \"$tmp\"; exit 1; fi");
                await ExecuteConfigCommandAsync("systemctl restart miga_server");
                await UpdateServerDemoStatusAsync();
                _dialogService.ShowInfo($"Конфигурация применена на сервере {DisplayName}, демон перезапущен.");
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Ошибка применения серверной конфигурации ({DisplayName}): {ex.Message}");
            }
        }

        private async Task<string> ExecuteConfigCommandAsync(string command)
        {
            const string marker = "\nMIGA_CONFIG_EXIT=";
            string output = await _sshManager.ExecuteCommandAsync(command + "; result=$?; printf '\\nMIGA_CONFIG_EXIT=%s\\n' \"$result\"");
            int index = output.LastIndexOf(marker, StringComparison.Ordinal);
            if (index < 0 || output[(index + marker.Length)..].Trim() != "0")
                throw new InvalidOperationException("Команда применения серверной конфигурации завершилась с ошибкой.");
            return output[..index];
        }
        public void DisconnectSsh()
        {
            try
            {
                _sshManager.Disconnect();
            }
            catch
            {
            }
            IsSshConnected = false;
            SshButtonText = "Подключиться";
        }
    }
}
