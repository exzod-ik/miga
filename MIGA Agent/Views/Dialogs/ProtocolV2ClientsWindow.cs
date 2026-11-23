using System.IO;
using System.Globalization;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using MIGA_Agent.Models;
using MIGA_Agent.Services;

namespace MIGA_Agent.Views.Dialogs;

public sealed class ProtocolV2ClientsWindow : Window
{
    private readonly ISshManager ssh;
    private readonly Func<string, Task> applyInvitation;
    private readonly ListBox clients = new() { HorizontalContentAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox maxSessions = new() { Text = "64", Width = 80 };
    private readonly TextBox name = new();
    private readonly TextBox limit = new() { Text = "1", Width = 80, HorizontalAlignment = HorizontalAlignment.Left };
    private readonly TextBox invitation = new()
    {
        IsReadOnly = true,
        TextWrapping = TextWrapping.Wrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        Padding = new Thickness(10, 6, 10, 6)
    };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly WrapPanel actions = new() { Margin = new Thickness(0, 8, 0, 4) };
    private readonly List<Button> selectedActions = [];
    private Button create = null!;
    private readonly TextBlock editorTitle = new() {Text = "Новое приглашение", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 6)};
    private sealed record ClientRow(string Id, string Name, int Limit, int Sessions)
    {
        public string Display => $"{Name} — подключений: {Sessions}, лимит: {(Limit == 0 ? "общий лимит сервера" : Limit.ToString(CultureInfo.InvariantCulture))}";
    }

    public ProtocolV2ClientsWindow(ISshManager ssh, Func<string, Task> applyInvitation, bool sharing = false)
    {
        this.ssh = ssh;
        this.applyInvitation = applyInvitation;
        Title = sharing ? "Поделиться — создать приглашение для устройства" : "Приглашения MIGA";
        Width = 960;
        Height = 565;
        MinWidth = 850;
        MinHeight = 530;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition());
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Content = root;

        var settings = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        settings.Children.Add(new Label { Content = "Максимум подключений сервера (1–512)", Target = maxSessions, VerticalAlignment = VerticalAlignment.Center, Padding = new Thickness(0, 0, 8, 0) });
        maxSessions.Margin = new Thickness(0, 0, 8, 0);
        settings.Children.Add(maxSessions);
        var saveSettings = new Button { Content = "Сохранить лимит сервера", Padding = new Thickness(12, 5, 12, 5) };
        saveSettings.Click += async (_, _) => await RunAsync(SaveSettingsAsync);
        settings.Children.Add(saveSettings);
        root.Children.Add(settings);

        var columns = new Grid();
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
        columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(5, GridUnitType.Star) });
        Grid.SetRow(columns, 1);
        root.Children.Add(columns);
        var list = new DockPanel { Margin = new Thickness(0, 0, 14, 0) };
        columns.Children.Add(list);
        var listTitle = new TextBlock { Text = "Список приглашений", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 8) };
        DockPanel.SetDock(listTitle, Dock.Top);
        list.Children.Add(listTitle);
        var clientText = new FrameworkElementFactory(typeof(TextBlock));
        clientText.SetBinding(TextBlock.TextProperty, new Binding(nameof(ClientRow.Display)));
        clientText.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap);
        clients.ItemTemplate = new DataTemplate { VisualTree = clientText };
        var clientStyle = new Style(typeof(ListBoxItem), TryFindResource(typeof(ListBoxItem)) as Style);
        clientStyle.Setters.Add(new Setter(HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));
        clients.ItemContainerStyle = clientStyle;
        ScrollViewer.SetHorizontalScrollBarVisibility(clients, ScrollBarVisibility.Disabled);
        ScrollViewer.SetVerticalScrollBarVisibility(clients, ScrollBarVisibility.Auto);
        ScrollViewer.SetCanContentScroll(clients, true);
        VirtualizingPanel.SetScrollUnit(clients, ScrollUnit.Pixel);
        var listActions = new WrapPanel { Margin = new Thickness(0, 8, 0, 0) };
        DockPanel.SetDock(listActions, Dock.Bottom);
        list.Children.Add(listActions);
        AddButton("Новое приглашение", () => { clients.SelectedItem = null; invitation.Clear(); name.Clear(); limit.Text = "1"; name.Focus(); return Task.CompletedTask; }, listActions);
        AddButton("Обновить список", RefreshAsync, listActions);
        list.Children.Add(clients);
        clients.SelectionChanged += (_, _) =>
        {
            invitation.Clear();
            if (clients.SelectedItem is ClientRow row)
            {
                editorTitle.Text = "Изменить приглашение";
                name.Text = row.Name;
                limit.Text = row.Limit.ToString(CultureInfo.InvariantCulture);
            }
            else { editorTitle.Text = "Новое приглашение"; name.Clear(); limit.Text = "1"; }
            foreach (var button in selectedActions) button.IsEnabled = clients.SelectedItem is ClientRow;
            create.IsEnabled = clients.SelectedItem == null;
        };
        var editor = new Grid();
        editor.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        editor.RowDefinitions.Add(new RowDefinition());
        editor.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        Grid.SetColumn(editor, 1);
        columns.Children.Add(editor);
        var fields = new StackPanel();
        editor.Children.Add(fields);
        fields.Children.Add(editorTitle);
        var identity = new Grid();
        identity.ColumnDefinitions.Add(new ColumnDefinition());
        identity.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var nameField = new StackPanel { Margin = new Thickness(0, 0, 12, 0) };
        nameField.Children.Add(new Label { Content = "Имя устройства или получателя", Target = name, Padding = new Thickness(0, 0, 0, 4) });
        nameField.Children.Add(name);
        identity.Children.Add(nameField);
        var limitField = new StackPanel();
        limitField.Children.Add(new Label { Content = "Лимит подключений (0 — общий)", Target = limit, Padding = new Thickness(0, 0, 0, 4) });
        limit.ToolTip = "Если указан 0, действует только общий лимит сервера.";
        limitField.Children.Add(limit);
        Grid.SetColumn(limitField, 1);
        identity.Children.Add(limitField);
        fields.Children.Add(identity);
        fields.Children.Add(actions);
        create = AddButton("Создать", AddAsync);
        selectedActions.Add(AddButton("Сохранить изменения", UpdateAsync));
        selectedActions.Add(AddButton("Отключить подключения", () => SelectedAsync("disconnect")));
        selectedActions.Add(AddButton("Отозвать приглашение", () => SelectedAsync("revoke")));
        foreach (var button in selectedActions) button.IsEnabled = false;

        var invitationPanel = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
        var invitationLabel = new Label
        {
            Content = "Приглашение для передачи",
            Target = invitation,
            FontWeight = FontWeights.SemiBold,
            Padding = new Thickness(0, 0, 0, 4)
        };
        DockPanel.SetDock(invitationLabel, Dock.Top);
        invitationPanel.Children.Add(invitationLabel);
        invitation.ToolTip = new TextBlock
        {
            Text = "Приглашение показано только после создания: сохраните файл или примените его до закрытия окна. Каждому устройству рекомендуется отдельное приглашение; лимит подключений действует на это приглашение. Изменение имени или лимита не создаёт новое приглашение.",
            MaxWidth = 340,
            TextWrapping = TextWrapping.Wrap
        };
        invitationPanel.Children.Add(invitation);
        Grid.SetRow(invitationPanel, 1);
        editor.Children.Add(invitationPanel);
        var export = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
        export.Children.Add(new TextBlock { Text = "Передавайте учётные данные только получателю.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) });
        var share = new Button
        {
            Content = "Поделиться / открыть в MIGA Client…",
            Padding = new Thickness(12, 5, 12, 5),
            IsEnabled = false
        };
        invitation.TextChanged += (_, _) => share.IsEnabled = !string.IsNullOrWhiteSpace(invitation.Text);
        share.Click += (_, _) => new InvitationWindow(applyInvitation, true, invitation.Text, true) { Owner = this }.ShowDialog();
        export.Children.Add(share);
        Grid.SetRow(export, 2);
        editor.Children.Add(export);
        status.Margin = new Thickness(0, 8, 0, 0);
        Grid.SetRow(status, 2);
        root.Children.Add(status);
        Closed += (_, _) => invitation.Clear();
        Loaded += async (_, _) => await RunAsync(RefreshAsync);
    }

    private Button AddButton(string text, Func<Task> action, Panel? panel = null)
    {
        var button = new Button { Content = text, Margin = new Thickness(0, 0, 6, 4), Padding = new Thickness(10, 5, 10, 5) };
        button.Click += async (_, _) => await RunAsync(action);
        (panel ?? actions).Children.Add(button);
        return button;
    }

    private async Task RunAsync(Func<Task> action)
    {
        ((UIElement)Content).IsEnabled = false;
        status.Text = "Выполняется…";
        try { await action(); status.Text = "Готово"; }
        catch (Exception error) { status.Text = SshCommandErrors.UserMessage(error); }
        finally { ((UIElement)Content).IsEnabled = true; }
    }

    private async Task RefreshAsync()
    {
        var rows = new List<ClientRow>();
        var cursors = new HashSet<string>(StringComparer.Ordinal);
        string? cursor = null;
        do
        {
            string options = cursor is null ? "" : " --after " + Quote(cursor);
            string json;
            int responseLimit = 128 * 1024;
            try
            {
                json = await ssh.ExecuteCheckedAsync("miga-server client list --page --json" + options);
            }
            catch (SshCommandFailure error) when (cursor is null && error.ExitStatus == 1)
            {
                json = await ssh.ExecuteCheckedAsync("miga-server client list --json");
                responseLimit = 1024 * 1024;
            }
            if (json.Length > responseLimit) throw new InvalidDataException();
            using var document = JsonDocument.Parse(json);
            var response = document.RootElement;
            bool legacy = cursor is null && response.ValueKind == JsonValueKind.Array;
            var page = legacy ? response : response.GetProperty("clients");
            foreach (var item in page.EnumerateArray())
                rows.Add(new(item.GetProperty("id").GetString() ?? "", item.GetProperty("name").GetString() ?? "", item.GetProperty("limit").GetInt32(), item.GetProperty("sessions").GetInt32()));
            cursor = legacy ? null : response.GetProperty("next").GetString();
            if (cursor is not null && !cursors.Add(cursor)) throw new InvalidDataException();
        }
        while (cursor is not null);
        rows = rows.OrderBy(row => row.Name, StringComparer.Ordinal).ToList();
        string? selectedId = (clients.SelectedItem as ClientRow)?.Id;
        clients.ItemsSource = rows;
        if (selectedId != null) clients.SelectedItem = rows.FirstOrDefault(row => row.Id == selectedId);
        string settings = await ssh.ExecuteCheckedAsync("miga-server settings get --json");
        if (settings.Length > 8192) throw new InvalidDataException();
        using var configuration = JsonDocument.Parse(settings);
        maxSessions.Text = configuration.RootElement.GetProperty("max_sessions").GetInt32().ToString(CultureInfo.InvariantCulture);
    }

    private async Task SaveSettingsAsync()
    {
        if (!int.TryParse(maxSessions.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int count) || count is < 1 or > 512)
            throw new InvalidDataException();
        await ssh.ExecuteCheckedAsync("miga-server settings set --max-sessions " + count.ToString(CultureInfo.InvariantCulture));
        await RefreshAsync();
    }

    private string Options()
    {
        if (string.IsNullOrWhiteSpace(name.Text) || name.Text.Length > 256 || name.Text.Contains('\0') || !int.TryParse(limit.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int count) || count < 0)
            throw new InvalidDataException();
        return " --name " + Quote(name.Text) + " --limit " + count.ToString(CultureInfo.InvariantCulture);
    }

    private async Task AddAsync()
    {
        invitation.Clear();
        string json = await ssh.ExecuteCheckedAsync("miga-server client add" + Options() + " --json");
        if (json.Length > 8192) throw new InvalidDataException();
        using var document = JsonDocument.Parse(json);
        string value = document.RootElement.GetProperty("invitation").GetString() ?? "";
        ProtocolV2Invitation.Parse(value);
        clients.SelectedItem = null;
        await RefreshAsync();
        invitation.Text = value;
    }

    private async Task UpdateAsync()
    {
        if (clients.SelectedItem is not ClientRow row) return;
        await ssh.ExecuteCheckedAsync("miga-server client update --id " + Quote(row.Id) + Options());
        await RefreshAsync();
    }

    private async Task SelectedAsync(string operation)
    {
        if (clients.SelectedItem is not ClientRow row) return;
        if (MessageBox.Show(this, operation == "revoke" ? "Отозвать приглашение и закрыть все его подключения?" : "Закрыть все подключения клиента?", Title, MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await ssh.ExecuteCheckedAsync("miga-server client " + operation + " --id " + Quote(row.Id));
        await RefreshAsync();
    }

    private static string Quote(string value)
    {
        if (value.Contains('\0')) throw new InvalidDataException();
        return "'" + value.Replace("'", "'\"'\"'") + "'";
    }
}
