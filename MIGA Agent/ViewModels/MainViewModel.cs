using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace MIGA_Agent.ViewModels
{
    /// <summary>
    /// Корневая модель главного окна: вкладки серверов, состояние локальной
    /// службы и запись конфига.
    /// </summary>
    public partial class MainViewModel : ObservableValidator
    {
        public Task Initialization { get; }

        private string _savedLogLevel = "none";
        private string _savedTunnelMaxMss = "1400";
        private bool _savedDnsResolverEnabled = true;
        private string _savedRoutingMode = "split";
        private string _savedFullRoutingProfileId = "";

        public IReadOnlyList<string> LogLevels { get; } = new[] { "none", "error", "warning", "info", "debug" };

        [ObservableProperty]
        [NotifyDataErrorInfo]
        [Required(ErrorMessage = "Укажите MSS: целое число от 1 до 65535.")]
        [Range(1, 65535, ErrorMessage = "MSS: целое число от 1 до 65535.")]
        private string _tunnelMaxMss = "1400";

        [ObservableProperty]
        private bool _dnsResolverEnabled = true;

        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(IsFullRouting))]
        [NotifyPropertyChangedFor(nameof(CanEditRules))]
        private string _routingMode = "split";

        [ObservableProperty]
        private ServerTabViewModel? _fullRoutingServer;

        public bool IsFullRouting => RoutingMode == "full";
        public bool CanEditRules => !IsFullRouting;
        private string FullRoutingProfileId => IsFullRouting ? FullRoutingServer?.ProfileId ?? "" : "";

        public bool IsDirty => LogLevel != _savedLogLevel || TunnelMaxMss != _savedTunnelMaxMss ||
            DnsResolverEnabled != _savedDnsResolverEnabled || RoutingMode != _savedRoutingMode || FullRoutingProfileId != _savedFullRoutingProfileId;

        partial void OnDnsResolverEnabledChanged(bool value) => NotifyClientSettingsChanged();
        partial void OnRoutingModeChanged(string value) => NotifyClientSettingsChanged();
        partial void OnFullRoutingServerChanged(ServerTabViewModel? value) => NotifyClientSettingsChanged();

        partial void OnLogLevelChanged(string value) => NotifyClientSettingsChanged();
        partial void OnTunnelMaxMssChanged(string value) => NotifyClientSettingsChanged();

        private void NotifyClientSettingsChanged()
        {
            OnPropertyChanged(nameof(IsDirty));
            OnPropertyChanged(nameof(HasUnsavedChanges));
            OnPropertyChanged(nameof(WindowTitle));
        }

        private const string BaseWindowTitle = "MIGA Client";

        private readonly ILocalServiceManager _localService;
        private readonly IClientConfigService _configService;
        private readonly IDialogService _dialogService;

        public MainViewModel(
            ILocalServiceManager localService,
            IClientConfigService configService,
            IDialogService dialogService)
        {
            _localService = localService;
            _configService = configService;
            _dialogService = dialogService;

            Servers = new ObservableCollection<ServerTabViewModel>();

            Servers.CollectionChanged += OnServersCollectionChanged;

            Initialization = Application.Current.Dispatcher.InvokeAsync(LoadInitialDataAsync).Task.Unwrap();
        }

        // ========== Публичные свойства ==========

        /// <summary>Вкладки серверов (одна вкладка — один сервер).</summary>
        public ObservableCollection<ServerTabViewModel> Servers { get; }

        [ObservableProperty]
        private ServerTabViewModel? _selectedServer;

        /// <summary>Глобальный уровень логирования клиента.</summary>
        [ObservableProperty]
        private string _logLevel = "none";

        [ObservableProperty]
        private string _serviceStatus = "Неизвестно";

        /// <summary>Есть несохранённые изменения хотя бы на одной вкладке.</summary>
        public bool HasUnsavedChanges => IsDirty || Servers.Any(t => t.IsDirty);

        /// <summary>Заголовок окна с индикатором несохранённых изменений.</summary>
        public string WindowTitle =>
            HasUnsavedChanges ? BaseWindowTitle + " *" : BaseWindowTitle;

        // ========== Команды ==========

        [RelayCommand(CanExecute = nameof(CanRefreshServiceStatus))]
        private async Task RefreshServiceStatus() => await UpdateServiceStatusAsync();

        private bool _serviceTransitionInProgress;
        private bool CanRefreshServiceStatus() => !_serviceTransitionInProgress;

        [RelayCommand(CanExecute = nameof(CanStartLocalService))]
        private async Task StartLocalService() => await StartLocalServiceAsync();
        private bool CanStartLocalService() => !_serviceTransitionInProgress && ServiceStatus == "Остановлена";

        [RelayCommand(CanExecute = nameof(CanStopLocalService))]
        private async Task StopLocalService() => await StopLocalServiceAsync();
        private bool CanStopLocalService() => !_serviceTransitionInProgress && ServiceStatus == "Работает";

        [RelayCommand]
        private async Task ApplyConfiguration() => await ApplyConfigurationAsync();

        [RelayCommand]
        private void AddServer()
        {
            var tab = CreateServerTab();
            Servers.Add(tab);
            SelectedServer = tab;

            // Новый сервер ещё не записан в конфигурационный файл
            tab.IsDirty = true;
        }

        public async Task AddInvitationAsync(string value)
        {
            var invitation = ProtocolV2Invitation.Parse(value);
            if (!_dialogService.ShowYesNo($"Добавить новое подключение к {invitation.Host}? Существующие подключения и правила сохранятся.", "MIGA Client")) return;
            var tab = CreateServerTab();
            Servers.Add(tab);
            SelectedServer = tab;
            try { await tab.ApplyInvitationAsync(value); }
            catch { UnhookTabHandlers(tab); Servers.Remove(tab); SelectedServer = Servers.FirstOrDefault(); throw; }
        }

        // ========== Инициализация ==========

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
            LogLevel = config.LogLevel;
            TunnelMaxMss = config.TunnelMaxMss.ToString();
            _savedLogLevel = LogLevel;
            _savedTunnelMaxMss = TunnelMaxMss;
            _savedDnsResolverEnabled = config.DnsResolverEnabled;
            _savedRoutingMode = config.RoutingMode;
            _savedFullRoutingProfileId = config.FullRoutingProfileId;

            foreach (var entry in config.Servers)
            {
                var tab = CreateServerTab();
                tab.LoadFrom(entry);
                Servers.Add(tab);
            }

            // Минимум одна вкладка всегда должна существовать
            if (Servers.Count == 0)
                Servers.Add(CreateServerTab());

            SelectedServer = Servers.FirstOrDefault();
            DnsResolverEnabled = config.DnsResolverEnabled;
            RoutingMode = config.RoutingMode;
            FullRoutingServer = Servers.FirstOrDefault(tab => tab.CanUseForFullRouting && tab.ProfileId == config.FullRoutingProfileId);
            NotifyClientSettingsChanged();

            // Подсветка пересечений, сохранённых в конфиге ранее
            RecalculateConflicts();
        }

        // ========== Фабрика вкладок ==========

        private ServerTabViewModel CreateServerTab()
        {
            var tab = new ServerTabViewModel(
                _localService,
                _dialogService,
                ReloadLocalServiceAsync,
                PersistInvitationConfigAsync);

            tab.RemoveRequested += OnTabRemoveRequested;
            tab.PropertyChanged += OnTabPropertyChanged;
            tab.RedirectProcesses.CollectionChanged += OnTabItemsChanged;
            tab.RedirectIps.CollectionChanged += OnTabItemsChanged;
            tab.RedirectDomains.CollectionChanged += OnTabItemsChanged;

            return tab;
        }

        private void UnhookTabHandlers(ServerTabViewModel tab)
        {
            tab.RemoveRequested -= OnTabRemoveRequested;
            tab.PropertyChanged -= OnTabPropertyChanged;
            tab.RedirectProcesses.CollectionChanged -= OnTabItemsChanged;
            tab.RedirectIps.CollectionChanged -= OnTabItemsChanged;
            tab.RedirectDomains.CollectionChanged -= OnTabItemsChanged;
        }

        private void OnServersCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (FullRoutingServer != null && !Servers.Contains(FullRoutingServer))
                FullRoutingServer = null;
            OnPropertyChanged(nameof(WindowTitle));
        }

        private void OnTabPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ServerTabViewModel.IsDirty))
            {
                OnPropertyChanged(nameof(HasUnsavedChanges));
                OnPropertyChanged(nameof(WindowTitle));
            }
            if (e.PropertyName == nameof(ServerTabViewModel.Enabled))
                RecalculateConflicts();
            if (ReferenceEquals(sender, FullRoutingServer) && e.PropertyName == nameof(ServerTabViewModel.ProfileId))
                NotifyClientSettingsChanged();
        }

        private void OnTabItemsChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            RecalculateConflicts();
        }

        /// <summary>Кнопка "Удалить сервер" на вкладке.</summary>
        private void OnTabRemoveRequested(object? sender, EventArgs e)
        {
            if (sender is not ServerTabViewModel tab)
                return;

            if (Servers.Count <= 1)
            {
                _dialogService.ShowWarning("Должен остаться хотя бы один сервер.");
                return;
            }

            if (!_dialogService.ShowYesNo(
                    $"Удалить сервер «{tab.DisplayName}»?\n\nНастройки будут удалены из конфигурации при следующем применении.",
                    "Удаление сервера"))
            {
                return;
            }

            UnhookTabHandlers(tab);
            Servers.Remove(tab);

            if (SelectedServer == null)
                SelectedServer = Servers.FirstOrDefault();

            RecalculateConflicts();

            // Удаление сервера меняет состав конфигурации — помечаем как несохранённое
            foreach (var t in Servers.ToList())
                t.IsDirty = true;
        }

        // ========== Конфигурация ==========

        private async Task<bool> PersistInvitationConfigAsync()
        {
            if (FullRoutingValidationError() != null)
                return false;
            await SaveClientConfigAsync();
            return true;
        }

        private async Task SaveClientConfigAsync()
        {
            ValidateAllProperties();
            if (HasErrors)
                throw new InvalidOperationException("MSS должен быть целым числом от 1 до 65535.");
            var draft = Servers.FirstOrDefault(tab => !tab.RequiresInvitation && string.IsNullOrWhiteSpace(tab.ProfileId) &&
                (!string.IsNullOrWhiteSpace(tab.ConnectionName) || tab.RedirectProcesses.Count > 0 ||
                    tab.RedirectIps.Count > 0 || tab.RedirectDomains.Count > 0));
            if (draft != null)
            {
                SelectedServer = draft;
                throw new InvalidOperationException($"Для сохранения вкладки «{draft.DisplayName}» добавьте приглашение.");
            }
            string savedMssText = TunnelMaxMss;
            var config = new ClientConfig
            {
                LogLevel = LogLevel,
                TunnelMaxMss = int.Parse(TunnelMaxMss),
                DnsResolverEnabled = DnsResolverEnabled,
                RoutingMode = RoutingMode,
                FullRoutingProfileId = FullRoutingProfileId,
                Servers = Servers.Where(t => t.RequiresInvitation || !string.IsNullOrWhiteSpace(t.ProfileId)).Select(t => t.ToServerEntry()).ToList()
            };
            await _configService.SaveAsync(config);
            _savedLogLevel = config.LogLevel;
            _savedTunnelMaxMss = savedMssText;
            _savedDnsResolverEnabled = config.DnsResolverEnabled;
            _savedRoutingMode = config.RoutingMode;
            _savedFullRoutingProfileId = config.FullRoutingProfileId;
            NotifyClientSettingsChanged();

            // Всё записано в файл — сбрасываем признак несохранённых изменений
            foreach (var tab in Servers.ToList())
                tab.MarkClean();
        }

        /// <summary>
        /// Подтверждение закрытия окна при наличии несохранённых изменений.
        /// Возвращает true, если окно можно закрывать.
        /// </summary>
        public async Task<bool> ConfirmClosingAsync()
        {
            var decision = _dialogService.ShowUnsavedChangesDialog(
                "Изменения ещё не записаны в файл конфигурации.\nСохранить изменения перед закрытием?",
                "Несохранённые изменения");

            switch (decision)
            {
                case UnsavedChangesDecision.Save:
                    if (!ValidateClientSettings())
                        return false;
                    var issues = GetConflictIssues();
                    if (issues.Count > 0 && !_dialogService.ShowIssuesConfirmation(
                            "Обнаружены пересечения настроек",
                            "Настройки перенаправления пересекаются между серверами. Список проблем:",
                            issues))
                    {
                        // Пользователь отменил запись — окно остаётся открытым
                        return false;
                    }
                    try
                    {
                        await SaveClientConfigAsync();
                        return true;
                    }
                    catch (Exception error)
                    {
                        _dialogService.ShowError($"Не удалось сохранить конфигурацию: {error.Message}");
                        return false;
                    }

                case UnsavedChangesDecision.Discard:
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// Применение всей конфигурации: проверка пересечений, сохранение,
        /// перезапуск службы.
        /// </summary>
        private async Task ApplyConfigurationAsync()
        {
            if (!ValidateClientSettings())
                return;

            var issues = GetConflictIssues();
            if (issues.Count > 0)
            {
                bool applyAnyway = _dialogService.ShowIssuesConfirmation(
                    "Обнаружены пересечения настроек",
                    "Настройки перенаправления пересекаются между серверами. Список проблем:",
                    issues);

                if (!applyAnyway)
                    return;
            }

            try
            {
                await SaveClientConfigAsync();
            }
            catch (Exception error)
            {
                _dialogService.ShowError($"Не удалось сохранить конфигурацию: {error.Message}");
                return;
            }

            await ReloadLocalServiceAsync();
        }

        private bool ValidateClientSettings()
        {
            ValidateAllProperties();
            if (HasErrors)
            {
                _dialogService.ShowError("MSS должен быть целым числом от 1 до 65535.");
                return false;
            }
            var routingError = FullRoutingValidationError();
            if (routingError == null) return true;
            _dialogService.ShowError(routingError);
            return false;
        }

        private string? FullRoutingValidationError()
        {
            if (!IsFullRouting) return null;
            if (FullRoutingServer?.CanUseForFullRouting != true)
                return "Выберите включённое подключение с приглашением для полного перенаправления.";
            if (Servers.Any(server => server.Enabled && server.RequiresInvitation))
                return "Добавьте приглашения для включённых подключений, перенесённых из старой конфигурации, или отключите эти подключения.";
            if (Servers.Count(server => server.Enabled && server.ProfileId == FullRoutingProfileId) != 1)
                return "Выбранное приглашение используется в нескольких подключениях. Удалите дубликаты.";
            return null;
        }

        // ========== Проверка пересечений ==========

        private enum RedirectKind
        {
            Process,
            Ip,
            Domain
        }

        private static string KindName(RedirectKind kind) => kind switch
        {
            RedirectKind.Process => "Процесс",
            RedirectKind.Ip => "IP",
            _ => "Домен"
        };

        private static ObservableCollection<RedirectItemViewModel> ItemsOf(ServerTabViewModel tab, RedirectKind kind) => kind switch
        {
            RedirectKind.Process => tab.RedirectProcesses,
            RedirectKind.Ip => tab.RedirectIps,
            _ => tab.RedirectDomains
        };

        /// <summary>
        /// Пересчитывает признак пересечения и подсказку для каждого элемента перенаправления.
        /// Пересечение — значение встречается минимум у двух серверов.
        /// </summary>
        private void RecalculateConflicts()
        {
            var tabs = Servers.ToList();

            foreach (var tab in tabs)
            {
                foreach (var item in tab.RedirectProcesses.Concat(tab.RedirectIps).Concat(tab.RedirectDomains))
                {
                    item.IsConflicting = false;
                    item.ConflictTooltip = string.Empty;
                }
            }

            var enabledTabs = tabs.Where(tab => tab.Enabled).ToList();
            RecalculateCategory(RedirectKind.Process, enabledTabs);
            RecalculateCategory(RedirectKind.Ip, enabledTabs);
            RecalculateCategory(RedirectKind.Domain, enabledTabs);
        }

        private void RecalculateCategory(RedirectKind kind, List<ServerTabViewModel> tabs)
        {
            var map = new Dictionary<string, List<(ServerTabViewModel Tab, RedirectItemViewModel Item)>>(StringComparer.OrdinalIgnoreCase);

            foreach (var tab in tabs)
            {
                foreach (var item in ItemsOf(tab, kind))
                {
                    if (!map.TryGetValue(item.Value, out var list))
                        map[item.Value] = list = new List<(ServerTabViewModel, RedirectItemViewModel)>();
                    list.Add((tab, item));
                }
            }

            foreach (var (value, owners) in map)
            {
                if (owners.Count < 2)
                    continue;

                foreach (var (tab, item) in owners)
                {
                    var others = owners
                        .Where(o => o.Tab != tab)
                        .Select(o => o.Tab.DisplayName)
                        .Distinct()
                        .ToList();
                    if (others.Count == 0)
                        continue;

                    item.IsConflicting = true;
                    item.ConflictTooltip =
                        $"Пересечение: {KindName(kind)} «{item.Value}» также используется на серверах: {string.Join(", ", others)}";
                }
            }
        }

        /// <summary>Список проблем пересечений для показа перед записью конфига.</summary>
        private List<string> GetConflictIssues()
        {
            var issues = new List<string>();
            if (IsFullRouting) return issues;
            issues.AddRange(GetCategoryIssues(RedirectKind.Process));
            issues.AddRange(GetCategoryIssues(RedirectKind.Ip));
            issues.AddRange(GetCategoryIssues(RedirectKind.Domain));
            return issues;
        }

        private IEnumerable<string> GetCategoryIssues(RedirectKind kind)
        {
            var map = new Dictionary<string, List<ServerTabViewModel>>(StringComparer.OrdinalIgnoreCase);

            foreach (var tab in Servers.Where(tab => tab.Enabled))
            {
                foreach (var item in ItemsOf(tab, kind))
                {
                    if (!map.TryGetValue(item.Value, out var list))
                        map[item.Value] = list = new List<ServerTabViewModel>();
                    if (!list.Contains(tab))
                        list.Add(tab);
                }
            }

            foreach (var (value, tabs) in map.Where(kv => kv.Value.Count > 1))
            {
                yield return $"{KindName(kind)} \"{value}\" назначен нескольким серверам: {string.Join(", ", tabs.Select(tab => tab.DisplayName))}";
            }
        }

        // ========== Локальная служба ==========

        private long _serviceStatusRequest;

        private async Task UpdateServiceStatusAsync()
        {
            var request = ++_serviceStatusRequest;
            try
            {
                var status = await Task.Run(_localService.GetStatus);
                if (request != _serviceStatusRequest) return;
                ServiceStatus = status switch
                {
                    System.ServiceProcess.ServiceControllerStatus.Running => "Работает",
                    System.ServiceProcess.ServiceControllerStatus.Stopped => "Остановлена",
                    System.ServiceProcess.ServiceControllerStatus.StartPending => "Запускается…",
                    System.ServiceProcess.ServiceControllerStatus.StopPending => "Останавливается…",
                    System.ServiceProcess.ServiceControllerStatus.Paused => "Приостановлена",
                    System.ServiceProcess.ServiceControllerStatus.PausePending => "Приостановка…",
                    System.ServiceProcess.ServiceControllerStatus.ContinuePending => "Возобновляется…",
                    null => "Не найдена",
                    _ => "Неизвестно"
                };
            }
            catch (Exception ex)
            {
                if (request != _serviceStatusRequest) return;
                ServiceStatus = "Ошибка";
                _dialogService.ShowError($"Не удалось получить статус службы: {ex.Message}");
            }

            // Обновляем состояние кнопок "Запустить"/"Остановить"
            (StartLocalServiceCommand as IAsyncRelayCommand)?.NotifyCanExecuteChanged();
            (StopLocalServiceCommand as IAsyncRelayCommand)?.NotifyCanExecuteChanged();
        }

        private Task StartLocalServiceAsync() => ChangeServiceStateAsync(
            _localService.Start, "Запускается…", "Служба запущена", "Ошибка запуска службы");

        private Task StopLocalServiceAsync() => ChangeServiceStateAsync(
            _localService.Stop, "Останавливается…", "Служба остановлена", "Ошибка остановки службы");

        private async Task ChangeServiceStateAsync(Action operation, string pending, string success, string failure)
        {
            if (_serviceTransitionInProgress) return;
            _serviceTransitionInProgress = true;
            ++_serviceStatusRequest;
            ServiceStatus = pending;
            RefreshServiceStatusCommand.NotifyCanExecuteChanged();
            StartLocalServiceCommand.NotifyCanExecuteChanged();
            StopLocalServiceCommand.NotifyCanExecuteChanged();

            string? error = null;
            try
            {
                await Task.Run(operation);
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }
            finally
            {
                await UpdateServiceStatusAsync();
                _serviceTransitionInProgress = false;
                RefreshServiceStatusCommand.NotifyCanExecuteChanged();
                StartLocalServiceCommand.NotifyCanExecuteChanged();
                StopLocalServiceCommand.NotifyCanExecuteChanged();
            }
            if (error == null) _dialogService.ShowInfo(success);
            else _dialogService.ShowError(error, failure);
        }

        private async Task<bool> ReloadLocalServiceAsync()
        {
            try
            {
                if (await Task.Run(() => _localService.GetStatus()) != System.ServiceProcess.ServiceControllerStatus.Running)
                {
                    _dialogService.ShowInfo("Конфигурация сохранена и будет прочитана при запуске службы.");
                    return false;
                }

                await Task.Run(() => _localService.ReloadConfig());
                _dialogService.ShowInfo("Службе отправлен запрос на применение конфигурации без перезапуска. Результат применения записывается в журнал клиента.");
                return true;
            }
            catch (Exception ex)
            {
                _dialogService.ShowError($"Не удалось отправить запрос на применение конфигурации: {ex.Message}");
                return false;
            }
        }
    }
}
