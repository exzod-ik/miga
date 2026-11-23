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
using System.Text.Json;
using System.Text;
using System.Windows;
using System.Threading.Tasks;

namespace MIGA_Agent.ViewModels
{
    public partial class ServerTabViewModel : ObservableObject
    {
        private readonly ILocalServiceManager _localService;
        private readonly IDialogService _dialogService;
        private const string PendingInvitationsStatus = "Туннели отключены до применения настроек. Добавьте приглашения для остальных включённых подключений или отключите их.";

        /// <summary>Перезапуск локальной службы с предупреждением (реализует MainViewModel).</summary>
        private readonly Func<Task<bool>> _reloadLocalServiceAsync;

        /// <summary>Сохранение всего клиентского конфига (реализует MainViewModel).</summary>
        private readonly Func<Task<bool>> _persistConfigAsync;

        [RelayCommand]
        private void OpenDiagnostics()
        {
            try
            {
                var window = new DiagnosticsWindow(ServerIp, ProfileId) {Owner = Application.Current.MainWindow};
                window.Show();
            }
            catch (Exception error) { _dialogService.ShowError($"Не удалось открыть профиль диагностики: {error.Message}"); }
        }

        [RelayCommand]
        private async Task ImportInvitation()
        {
            if (IsBusy) return;
            var dialog = new OpenFileDialog { Title = "Загрузить приглашение", Filter = "Приглашение MIGA (*.miga)|*.miga|Текстовые файлы (*.txt)|*.txt|Все файлы (*.*)|*.*" };
            if (dialog.ShowDialog() != true) return;
            IsBusy = true;
            try
            {
                if (new FileInfo(dialog.FileName).Length > 16384)
                    throw new InvalidDataException("Файл приглашения слишком большой.");
                var value = (await File.ReadAllTextAsync(dialog.FileName)).Trim();
                await ApplyInvitationAsync(value);
            }
            catch (Exception error)
            {
                _dialogService.ShowError(error is InvalidDataException ? error.Message : "Не удалось импортировать приглашение. Проверьте доступность службы и права администратора.");
            }
            finally { IsBusy = false; }
        }

        [RelayCommand]
        private async Task ImportQr()
        {
            if (IsBusy) return;
            var dialog = new OpenFileDialog { Title = "QR приглашения", Filter = "Изображения (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp" };
            if (dialog.ShowDialog() != true) return;
            IsBusy = true;
            try { await ApplyInvitationAsync(InvitationQrReader.Read(dialog.FileName)); }
            catch (Exception error) { _dialogService.ShowError(error is InvalidDataException ? error.Message : "Не удалось прочитать приглашение из QR."); }
            finally { IsBusy = false; }
        }

        public async Task ApplyInvitationAsync(string value)
        {
            var invitation = ProtocolV2Invitation.Parse(value);
            await ProtocolV2ProfileService.EnsureReadyAsync(_localService);
            var id = await new ProtocolV2ProfileService().ImportAsync(value.Trim());
            ProfileId = id;
            RequiresInvitation = false;
            ConnectionStatus = "Проверка туннеля…";
            ServerIp = invitation.Host;
            ControlPortsStart = invitation.FirstPort;
            ControlPortsEnd = invitation.LastPort;
            MarkDirty();
            if (!await _persistConfigAsync())
            {
                ConnectionStatus = "Приглашение импортировано. Завершите настройку полного режима и примените конфигурацию.";
                return;
            }
            try { await Task.Run(_localService.ReloadConfig); }
            catch
            {
                ConnectionStatus = "Приглашение сохранено. Не удалось перезагрузить службу; запустите её повторно.";
                return;
            }
            var config = await new ClientConfigService().LoadAsync();
            if (config.Servers.Any(server => server.Enabled && server.RequiresInvitation))
                ConnectionStatus = PendingInvitationsStatus;
            else
                await RefreshProtocolV2StatusAsync();
        }

        [RelayCommand]
        private void PasteInvitation()
        {
            if (IsBusy) return;
            new InvitationWindow(ApplyInvitationAsync, false) { Owner = Application.Current.MainWindow }.ShowDialog();
        }

        [RelayCommand]
        private async Task ShareInvitation()
        {
            if (IsBusy) return;
            if (string.IsNullOrWhiteSpace(ProfileId)) { _dialogService.ShowWarning("Сначала добавьте приглашение."); return; }
            IsBusy = true;
            try
            {
                await ProtocolV2ProfileService.EnsureReadyAsync(_localService);
                string value = await new ProtocolV2ProfileService().ExportAsync(ProfileId);
                new InvitationWindow(null, true, value) { Owner = Application.Current.MainWindow }.ShowDialog();
            }
            catch { _dialogService.ShowError("Не удалось получить сохранённое приглашение. Проверьте службу и права администратора."); }
            finally { IsBusy = false; }
        }

        [ObservableProperty]
        private bool _requiresInvitation;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(DisplayedConnectionStatus))]
        private string _connectionStatus = "Не настроен: добавьте приглашение";

        public string DisplayedConnectionStatus => Enabled ? ConnectionStatus : "Подключение отключено в настройках";

        [RelayCommand]
        private async Task CheckProtocolV2Status()
        {
            if (IsBusy) return;
            if (string.IsNullOrEmpty(ProfileId))
            {
                _dialogService.ShowWarning("Сначала импортируйте приглашение MIGA.");
                return;
            }
            IsBusy = true;
            try
            {
                await RefreshProtocolV2StatusAsync();
            }
            finally { IsBusy = false; }
        }

        private async Task RefreshProtocolV2StatusAsync()
        {
            var serviceStatus = await Task.Run(_localService.GetStatus);
            if (serviceStatus != System.ServiceProcess.ServiceControllerStatus.Running)
            {
                ConnectionStatus = serviceStatus == null
                    ? "Не удалось получить состояние службы MigaClient. Проверьте установку и права администратора."
                    : serviceStatus == System.ServiceProcess.ServiceControllerStatus.StartPending
                        ? "Служба MigaClient запускается. Повторите проверку подключения."
                        : "Служба MigaClient не запущена. Нажмите «Запустить».";
                return;
            }
            ClientConfig config;
            try { config = await new ClientConfigService().LoadAsync(); }
            catch
            {
                ConnectionStatus = "Не удалось прочитать сохранённую конфигурацию. Проверьте файл настроек клиента.";
                return;
            }
            if (config.Servers.Any(server => server.Enabled && server.RequiresInvitation))
            {
                ConnectionStatus = PendingInvitationsStatus;
                return;
            }
            try
            {
                var state = await new ProtocolV2ProfileService().GetStatusAsync(ProfileId ?? throw new InvalidOperationException());
                ConnectionStatus = state switch
                {
                    "ready" => "Подключено",
                    "connecting" => "Подключение выполняется",
                    "recovering" => "Восстановление подключения",
                    _ => "Сервер недоступен, приглашение недействительно либо расходится время"
                };
            }
            catch
            {
                ConnectionStatus = "Не удалось проверить подключение. Проверьте службу и права администратора.";
            }
        }

        /// <summary>Вкладка просит удалить сервер (вкладку).</summary>
        public event EventHandler? RemoveRequested;

        /// <summary>Свойства, изменение которых означает несохранённые правки конфига.</summary>
        private static readonly HashSet<string> ConfigProperties = new()
        {
            nameof(ServerIp),
            nameof(ConnectionName),
            nameof(Enabled),
            nameof(ProfileId),
            nameof(RequiresInvitation),
            nameof(ControlPortsStart),
            nameof(ControlPortsEnd)
        };

        public ServerTabViewModel(
            ILocalServiceManager localService,
            IDialogService dialogService,
            Func<Task<bool>> reloadLocalServiceAsync,
            Func<Task<bool>> persistConfigAsync)
        {
            _localService = localService;
            _dialogService = dialogService;
            _reloadLocalServiceAsync = reloadLocalServiceAsync;
            _persistConfigAsync = persistConfigAsync;

            LogLevels = new List<string> { "none", "error", "warning", "info", "debug" };

            PropertyChanged += OnSelfPropertyChanged;
            RedirectProcesses.CollectionChanged += (_, _) => MarkDirty();
            RedirectIps.CollectionChanged += (_, _) => MarkDirty();
            RedirectDomains.CollectionChanged += (_, _) => MarkDirty();
        }

        // ========== Публичные свойства ==========

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(TabTitle))]
        [NotifyPropertyChangedFor(nameof(CanUseForFullRouting))]
        [NotifyPropertyChangedFor(nameof(DisplayedConnectionStatus))]
        private bool _enabled = true;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(DisplayName))]
        [NotifyPropertyChangedFor(nameof(TabTitle))]
        private string _connectionName = string.Empty;

        [ObservableProperty]
        private string? _profileId;

        public string InvitationMenuTitle => RequiresInvitation || string.IsNullOrWhiteSpace(ProfileId) ? "Настроить" : "Изменить приглашение";
        public bool CanUseForFullRouting => Enabled && !RequiresInvitation && !string.IsNullOrWhiteSpace(ProfileId);

        partial void OnProfileIdChanged(string? value)
        {
            OnPropertyChanged(nameof(InvitationMenuTitle));
            OnPropertyChanged(nameof(CanUseForFullRouting));
        }

        partial void OnRequiresInvitationChanged(bool value)
        {
            OnPropertyChanged(nameof(InvitationMenuTitle));
            OnPropertyChanged(nameof(CanUseForFullRouting));
        }


        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(DisplayName))]
        [NotifyPropertyChangedFor(nameof(TabTitle))]
        private string _serverIp = string.Empty;

        [ObservableProperty]
        private int _controlPortsStart = 10000;

        [ObservableProperty]
        private int _controlPortsEnd = 15000;

        [ObservableProperty]
        private bool _isBusy = false;

        public bool IsNotBusy => !IsBusy;

        partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(IsNotBusy));

        /// <summary>Есть несохранённые изменения на вкладке.</summary>
        [ObservableProperty]
        private bool _isDirty;

        private bool _suppressDirty;

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
            string.IsNullOrWhiteSpace(ConnectionName) ? (string.IsNullOrWhiteSpace(ServerIp) ? "Новый сервер" : ServerIp) : ConnectionName;

        public string TabTitle => Enabled ? DisplayName : DisplayName + " · отключён";

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
                Enabled = entry.Enabled;
                ProfileId = entry.ProfileId;
                RequiresInvitation = entry.RequiresInvitation;
                ConnectionStatus = RequiresInvitation || string.IsNullOrWhiteSpace(ProfileId) ? "Не настроен: добавьте приглашение" : "Подключение не проверено";
                ConnectionName = entry.ConnectionName;
                ServerIp = entry.ServerIp;
                ControlPortsStart = entry.ControlPorts.Start;
                ControlPortsEnd = entry.ControlPorts.End;

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
            Protocol = 2,
            Enabled = Enabled,
            ProfileId = ProfileId,
            RequiresInvitation = RequiresInvitation,
            ConnectionName = ConnectionName,
            ServerIp = ServerIp,
            ControlPorts = new PortRange { Start = ControlPortsStart, End = ControlPortsEnd },
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

            var values = ParseInput(input);
            if (collection == RedirectIps && values.Any(value => !ClientConfigCodec.IsValidIpRule(value)))
            {
                _dialogService.ShowError("Введите корректный IPv4-адрес или диапазон IPv4 от меньшего адреса к большему.");
                return;
            }
            foreach (var value in values)
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

            var values = ParseInput(input);
            if (collection == RedirectIps && values.Any(value => !ClientConfigCodec.IsValidIpRule(value)))
            {
                _dialogService.ShowError("Введите корректный IPv4-адрес или диапазон IPv4 от меньшего адреса к большему.");
                return;
            }
            SetItems(collection, values);
        }

        private void RemoveItem(ObservableCollection<RedirectItemViewModel> collection, object? item, string title)
        {
            if (item is not RedirectItemViewModel redirectItem)
                return;

            if (_dialogService.ShowYesNo($"Удалить {redirectItem.Value}?", title))
                collection.Remove(redirectItem);
        }

    }
}
