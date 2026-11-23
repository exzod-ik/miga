using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using MIGA_Agent.Services;
using MIGA_Agent.ViewModels;

namespace MIGA_Agent;

public partial class AdminWindow : Window
{
    private readonly IDialogService dialogs;
    private readonly AdminConfigService config = new();
    private readonly ObservableCollection<ManagedServerViewModel> servers = new();
    private readonly AdminServerAutosave autosave;
    private readonly double populatedMinHeight;
    private double? populatedHeight;
    private bool ready;
    private bool closing;
    private bool savingOnClose;

    public AdminWindow(IDialogService dialogs, NotificationCenter notifications)
    {
        InitializeComponent();
        this.dialogs = dialogs;
        autosave = new AdminServerAutosave(entries => config.SaveAsync(entries), () => { foreach (var server in servers) server.MarkClean(); }, _ => dialogs.ShowError("Не удалось сохранить список серверов. Изменения остаются в окне; повторите сохранение."));
        Tabs.ItemsSource = servers;
        populatedMinHeight = MinHeight;
        servers.CollectionChanged += (_, _) => UpdateServerListHeight();
        Notifications.ItemsSource = notifications.Items;
        Loaded += async (_, _) => await LoadAsync();
        Closed += (_, _) => { foreach (var server in servers) server.DisconnectSsh(); };
    }

    private void UpdateServerListHeight()
    {
        if (servers.Count == 0)
        {
            populatedHeight = WindowState == WindowState.Normal ? ActualHeight : RestoreBounds.Height;
            MinHeight = 175;
            Height = 190;
        }
        else if (populatedHeight is double previousHeight)
        {
            MinHeight = populatedMinHeight;
            Height = Math.Max(previousHeight, populatedMinHeight);
            populatedHeight = null;
        }
    }

    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.OriginalSource != Tabs) return;
        _ = Dispatcher.InvokeAsync(() =>
        {
            if (Tabs.SelectedItem is { } item && Tabs.ItemContainerGenerator.ContainerFromItem(item) is TabItem tab)
                tab.BringIntoView();
        }, System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private async Task LoadAsync()
    {
        try
        {
            string legacy = Path.Combine(AppContext.BaseDirectory, "config.json");
            foreach (var entry in await config.LoadAsync(legacy))
            {
                var server = CreateServer();
                server.ConnectionName = entry.Name;
                server.ServerIp = entry.Host;
                server.ServerSshUser = entry.User;
                server.MarkClean();
            }
            if (servers.Count == 0) CreateServer().MarkClean();
            Tabs.SelectedIndex = 0;
            ready = true;
        }
        catch { dialogs.ShowError("Список серверов повреждён или недоступен. Файл сохранён без изменений."); IsEnabled = false; }
    }

    private ManagedServerViewModel CreateServer()
    {
        var server = new ManagedServerViewModel(dialogs, new SshManager());
        server.PropertyChanged += ServerChanged;
        servers.Add(server);
        Tabs.SelectedItem = server;
        return server;
    }

    private void ServerChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ManagedServerViewModel.ConnectionName) or nameof(ManagedServerViewModel.ServerIp) or nameof(ManagedServerViewModel.ServerSshUser)) ScheduleSave();
    }

    private void ScheduleSave()
    {
        if (ready) autosave.Schedule(servers.Select(s => new ManagedServerEntry(s.ConnectionName, s.ServerIp, s.ServerSshUser)));
    }

    private void ProjectLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        e.Handled = true;
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true })?.Dispose();
        }
        catch (Win32Exception)
        {
            dialogs.ShowError("Не удалось открыть ссылку в браузере.", "GitHub");
        }
    }

    private void Add_Click(object sender, RoutedEventArgs e) { CreateServer().IsDirty = true; ScheduleSave(); }

    private async Task SaveAsync()
    {
        await autosave.FlushAsync();
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (!ready) return;
        try { await SaveAsync(); }
        catch { dialogs.ShowError("Не удалось сохранить список серверов."); }
    }

    private async void Remove_Click(object sender, RoutedEventArgs e)
    {
        if (!ready || Tabs.SelectedItem is not ManagedServerViewModel server || !dialogs.ShowYesNo("Удалить сервер из списка Admin? Клиентские подключения сохранятся.", "MIGA Admin")) return;
        server.DisconnectSsh();
        server.PropertyChanged -= ServerChanged;
        servers.Remove(server);
        ScheduleSave();
        try { await SaveAsync(); }
        catch { dialogs.ShowError("Не удалось сохранить список серверов."); }
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        if (closing) return;
        if (savingOnClose) { e.Cancel = true; return; }
        if (servers.Any(s => s.IsBusy)) { dialogs.ShowWarning("Дождитесь завершения операции управления сервером."); e.Cancel = true; return; }
        if (ready && autosave.HasPending)
        {
            e.Cancel = true;
            savingOnClose = true;
            IsEnabled = false;
            try
            {
                await SaveAsync();
                closing = true;
                _ = Dispatcher.BeginInvoke(new Action(Close));
            }
            catch { dialogs.ShowError("Не удалось сохранить список серверов. Окно остаётся открытым, чтобы изменения не потерялись."); }
            finally { savingOnClose = false; IsEnabled = true; }
            return;
        }
        foreach (var server in servers) server.DisconnectSsh();
    }
}
