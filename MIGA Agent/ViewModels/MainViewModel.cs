using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace MIGA_Agent.ViewModels
{
    /// <summary>
    /// Корневая модель главного окна: вкладки серверов, состояние локальной
    /// службы и запись конфига.
    /// </summary>
    public partial class MainViewModel : ObservableObject
    {
        private const string BaseWindowTitle = "Make Internet Greate Again";

        private readonly ILocalServiceManager _localService;
        private readonly IClientConfigService _configService;
        private readonly Func<ISshManager> _sshFactory;
        private readonly IDialogService _dialogService;

        public MainViewModel(
            ILocalServiceManager localService,
            IClientConfigService configService,
            Func<ISshManager> sshFactory,
            IDialogService dialogService)
        {
            _localService = localService;
            _configService = configService;
            _sshFactory = sshFactory;
            _dialogService = dialogService;

            Servers = new ObservableCollection<ServerTabViewModel>();

            Servers.CollectionChanged += OnServersCollectionChanged;

            Application.Current.Dispatcher.InvokeAsync(async () => await LoadInitialDataAsync());
        }

        // ========== Публичные свойства ==========

        /// <summary>Вкладки серверов (одна вкладка — один сервер).</summary>
        public ObservableCollection<ServerTabViewModel> Servers { get; }

        [ObservableProperty]
        private ServerTabViewModel? _selectedServer;

        /// <summary>Глобальный уровень логирования клиента (только чтение из конфига и запись при сохранении).</summary>
        [ObservableProperty]
        private string _logLevel = "none";

        [ObservableProperty]
        private string _serviceStatus = "Неизвестно";

        /// <summary>Есть несохранённые изменения хотя бы на одной вкладке.</summary>
        public bool HasUnsavedChanges => Servers.Any(t => t.IsDirty);

        /// <summary>Заголовок окна с индикатором несохранённых изменений.</summary>
        public string WindowTitle =>
            HasUnsavedChanges ? BaseWindowTitle + " *" : BaseWindowTitle;

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

            // Подсветка пересечений, сохранённых в конфиге ранее
            RecalculateConflicts();
        }

        // ========== Фабрика вкладок ==========

        private ServerTabViewModel CreateServerTab()
        {
            var tab = new ServerTabViewModel(
                _localService,
                _dialogService,
                _sshFactory(),
                RestartLocalServiceWithWarningAsync,
                SaveClientConfigAsync);

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
            OnPropertyChanged(nameof(WindowTitle));
        }

        private void OnTabPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ServerTabViewModel.IsDirty))
                OnPropertyChanged(nameof(WindowTitle));
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
            tab.DisconnectSsh();
            Servers.Remove(tab);

            if (SelectedServer == null)
                SelectedServer = Servers.FirstOrDefault();

            RecalculateConflicts();

            // Удаление сервера меняет состав конфигурации — помечаем как несохранённое
            foreach (var t in Servers.ToList())
                t.IsDirty = true;
        }

        // ========== Конфигурация ==========

        private async Task SaveClientConfigAsync()
        {
            var config = new ClientConfig
            {
                LogLevel = LogLevel,
                Servers = Servers.Select(t => t.ToServerEntry()).ToList()
            };
            await _configService.SaveAsync(config);

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
                    var issues = GetConflictIssues();
                    if (issues.Count > 0 && !_dialogService.ShowIssuesConfirmation(
                            "Обнаружены пересечения настроек",
                            "Настройки перенаправления пересекаются между серверами. Список проблем:",
                            issues))
                    {
                        // Пользователь отменил запись — окно остаётся открытым
                        return false;
                    }
                    await SaveClientConfigAsync();
                    return true;

                case UnsavedChangesDecision.Discard:
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// Применение всей конфигурации: проверка пересечений, сохранение,
        /// применение серверной части для подключённых вкладок, перезапуск службы.
        /// </summary>
        private async Task ApplyConfigurationAsync()
        {
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

            await SaveClientConfigAsync();

            if (Servers.Any(t => t.IsSshConnected))
            {
                foreach (var tab in Servers.ToList())
                    await tab.ApplyServerConfigIfConnectedAsync();
            }
            else
            {
                _dialogService.ShowInfo("Конфигурация клиента сохранена. Для применения на сервере установите SSH-подключение на нужной вкладке.");
            }

            // Предлагаем перезапустить локальную службу
            await RestartLocalServiceWithWarningAsync();
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

            RecalculateCategory(RedirectKind.Process, tabs);
            RecalculateCategory(RedirectKind.Ip, tabs);
            RecalculateCategory(RedirectKind.Domain, tabs);
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
                        .Select(o => o.Tab.DisplayName)
                        .Where(n => !string.Equals(n, tab.DisplayName, StringComparison.Ordinal))
                        .Distinct()
                        .ToList();

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
            issues.AddRange(GetCategoryIssues(RedirectKind.Process));
            issues.AddRange(GetCategoryIssues(RedirectKind.Ip));
            issues.AddRange(GetCategoryIssues(RedirectKind.Domain));
            return issues;
        }

        private IEnumerable<string> GetCategoryIssues(RedirectKind kind)
        {
            var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var tab in Servers)
            {
                foreach (var item in ItemsOf(tab, kind))
                {
                    if (!map.TryGetValue(item.Value, out var list))
                        map[item.Value] = list = new List<string>();
                    if (!list.Contains(tab.DisplayName))
                        list.Add(tab.DisplayName);
                }
            }

            foreach (var (value, serversList) in map.Where(kv => kv.Value.Count > 1))
            {
                yield return $"{KindName(kind)} \"{value}\" назначен нескольким серверам: {string.Join(", ", serversList)}";
            }
        }

        // ========== Локальная служба ==========

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
