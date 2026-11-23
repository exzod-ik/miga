using MIGA_Agent.Services;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;

namespace MIGA_Agent.Views.Dialogs;

public sealed class DiagnosticsWindow : Window
{
    private readonly string server;
    private readonly string profileId;
    private readonly Action updateMode;
    private readonly ComboBox mode = new() {ItemsSource = new[] {"Через выбранный сервер", "По правилам перенаправления"}, SelectedIndex = 0};
    private readonly TextBox pid = new() {Text = "", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly TextBox loadSeconds = new() {Text = "60", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly TextBox loadBytes = new() {Text = "64", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly TextBox loadRepeats = new() {Text = "1", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly TextBox loadRates = new() {Text = "100,250,500,1000,1500,2000"};
    private readonly TextBox pingSeconds = new() {Text = "60", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly TextBox directPingSeconds = new() {Text = "10", Width = 100, HorizontalAlignment = HorizontalAlignment.Left};
    private readonly Grid measurementSettings = new();
    private readonly TabControl pages = new();
    private readonly TabItem resultsPage = new() {Header = "Результаты"};
    private readonly TextBlock resultHint = new() {Text = "Здесь появятся результаты после запуска проверки.", TextWrapping = TextWrapping.Wrap};
    private readonly TextBlock measurementStatus = new() {TextWrapping = TextWrapping.Wrap};
    private readonly TextBlock current = new() {Text = "Готово к запуску", TextWrapping = TextWrapping.Wrap};
    private readonly StackPanel observations = new();
    private readonly List<(string key, CheckBox check)> steps = [];
    private readonly Button start = new() {Content = "Запустить", Padding = new Thickness(16, 6, 16, 6), Margin = new Thickness(0, 0, 8, 0)};
    private readonly Button stop = new() {Content = "Остановить", Padding = new Thickness(16, 6, 16, 6), Margin = new Thickness(0, 0, 8, 0), IsEnabled = false};
    private readonly StringBuilder report = new();
    private CancellationTokenSource? cancellation;
    private Process? helper;
    private TcpClient? tcp;
    private SslStream? tls;
    private StreamReader? controlReader;
    private StreamWriter? controlWriter;
    public DiagnosticsWindow(string server, string? profileId)
    {
        this.server = server;
        this.profileId = profileId ?? "";
        Title = $"Диагностика MIGA — {server}";
        Width = 720; Height = 450; MinWidth = 640; MinHeight = 440;
        Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Icon.ico"));
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var root = new DockPanel {Margin = new Thickness(16, 12, 16, 12)};
        var checks = new StackPanel();
        var context = new Grid {Margin = new Thickness(0, 0, 0, 10)};
        context.ColumnDefinitions.Add(new ColumnDefinition());
        context.ColumnDefinitions.Add(new ColumnDefinition());
        var modePanel = new StackPanel {Margin = new Thickness(0, 0, 16, 0)};
        AddField(modePanel, "Режим проверки", mode);
        var modeDescription = new TextBlock {TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0)};
        modePanel.Children.Add(modeDescription);
        context.Children.Add(modePanel);
        var pidPanel = new StackPanel();
        AddField(pidPanel, "PID приложения (необязательно)", pid);
        pid.ToolTip = "PID указан на вкладке «Подробности» Диспетчера задач.";
        pidPanel.Children.Add(new TextBlock {Text = "Для наблюдения за перехватом и маршрутом создайте сетевую активность в указанном приложении.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0)});
        Grid.SetColumn(pidPanel, 1);
        context.Children.Add(pidPanel);
        checks.Children.Add(context);

        var groups = new Grid();
        groups.ColumnDefinitions.Add(new ColumnDefinition());
        groups.ColumnDefinitions.Add(new ColumnDefinition());
        var connectivity = new StackPanel();
        connectivity.Children.Add(new TextBlock {Text = "Сетевые проверки", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4)});
        groups.Children.Add(connectivity);
        var measurements = new StackPanel();
        measurements.Children.Add(new TextBlock {Text = "Измерения", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4)});
        Grid.SetColumn(measurements, 1);
        groups.Children.Add(measurements);
        foreach (var (key, label) in new[] {("capture", "Перехват WinDivert"), ("route", "Выбор маршрута"), ("first_leg", "Windows ↔ сервер"), ("tcp", "TCP и TLS за сервером"), ("udp", "UDP за сервером"), ("mss", "Подбор MSS"), ("speed", "Скорость M-Lab NDT7"), ("load", "Потери под нагрузкой"), ("ping", "UDP-пинг до сервера"), ("direct_ping", "Прямой UDP-пинг до STUN")})
        {
            var selected = steps.Count < 5;
            var check = new CheckBox {Content = label, IsChecked = selected, MinHeight = 26, VerticalContentAlignment = VerticalAlignment.Center, Padding = new Thickness(8, 0, 0, 0)};
            steps.Add((key, check));
            (selected ? connectivity : measurements).Children.Add(check);
        }
        checks.Children.Add(groups);
        var measurementPage = new TabItem {Header = "Нагрузка и UDP-пинг"};
        ToolTipService.SetShowOnDisabled(measurementPage, true);
        void UpdateMode()
        {
            bool rules = mode.SelectedIndex == 1;
            bool observing = rules && !string.IsNullOrWhiteSpace(pid.Text) && pid.Text.Trim() != "0";
            pidPanel.Visibility = rules ? Visibility.Visible : Visibility.Collapsed;
            modeDescription.Text = rules
                ? "Используются сохранённые правила. Без PID проверяется трафик тестового процесса."
                : "Пробы идут через выбранный сервер независимо от сохранённых правил.";
            foreach (var item in steps)
            {
                bool available = !rules || (!observing && item.key is not "speed" and not "load" and not "ping") || item.key is "capture" or "route" or "direct_ping";
                item.check.IsEnabled = available;
                item.check.ToolTip = available ? null : "Недоступно при выбранном режиме или наблюдении приложения.";
            }
            measurementPage.IsEnabled = steps.Any(x => x.key is "load" or "ping" or "direct_ping" && x.check.IsEnabled && x.check.IsChecked == true);
            measurementPage.ToolTip = measurementPage.IsEnabled ? null : "Выберите нагрузку или UDP-пинг на вкладке «Проверки».";
        }
        foreach (var (key, check) in steps.Where(x => x.key is "load" or "ping" or "direct_ping"))
        {
            check.Checked += (_, _) => UpdateMode();
            check.Unchecked += (_, _) => UpdateMode();
        }
        updateMode = UpdateMode;
        mode.SelectionChanged += (_, _) => UpdateMode();
        pid.TextChanged += (_, _) => UpdateMode();
        UpdateMode();
        measurementSettings.ColumnDefinitions.Add(new ColumnDefinition());
        measurementSettings.ColumnDefinitions.Add(new ColumnDefinition());
        measurementSettings.RowDefinitions.Add(new RowDefinition {Height = GridLength.Auto});
        measurementSettings.RowDefinitions.Add(new RowDefinition {Height = GridLength.Auto});
        var load = new StackPanel {Margin = new Thickness(0, 0, 16, 0)};
        load.Children.Add(new TextBlock {Text = "Потери под нагрузкой", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6)});
        AddSetting(load, "Ступень, с (1–300)", loadSeconds);
        AddSetting(load, "UDP payload, байт (32–1200)", loadBytes);
        AddSetting(load, "Повторов нагрузки (1–5)", loadRepeats);
        AddField(load, "Ступени, пакетов/с через запятую", loadRates);
        measurementSettings.Children.Add(load);
        var ping = new StackPanel();
        ping.Children.Add(new TextBlock {Text = "UDP-пинг", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6)});
        AddSetting(ping, "До сервера, с (1–3600)", pingSeconds);
        AddSetting(ping, "Прямой до STUN, с (1–3600)", directPingSeconds);
        Grid.SetColumn(ping, 1);
        measurementSettings.Children.Add(ping);
        var timing = new TextBlock
        {
            Text = "При совместном выборе UDP-пинг до сервера работает весь нагрузочный прогон. Прямой пинг выполняется первым и отправляет UDP на stun.cloudflare.com:3478.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 0)
        };
        loadBytes.ToolTip = "Размер включает заголовок теста.";
        Grid.SetColumnSpan(timing, 2);
        Grid.SetRow(timing, 1);
        measurementSettings.Children.Add(timing);

        var resultPanel = new StackPanel();
        resultPanel.Children.Add(resultHint);
        resultPanel.Children.Add(observations);
        resultsPage.Content = PageBody(resultPanel);
        measurementPage.Content = PageBody(measurementSettings);
        pages.Items.Add(new TabItem {Header = "Проверки", Content = PageBody(checks)});
        pages.Items.Add(measurementPage);
        pages.Items.Add(resultsPage);
        pages.SelectedIndex = 0;

        var footer = new DockPanel {Margin = new Thickness(0, 8, 0, 0)};
        var buttons = new StackPanel {Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center};
        buttons.Children.Add(start);
        buttons.Children.Add(stop);
        var copy = new Button {Content = "Скопировать отчёт", Padding = new Thickness(12, 6, 12, 6)};
        copy.Click += (_, _) => {if (report.Length > 0) Clipboard.SetText(report.ToString());};
        buttons.Children.Add(copy);
        DockPanel.SetDock(buttons, Dock.Left);
        footer.Children.Add(buttons);
        var progress = new StackPanel();
        progress.Children.Add(current);
        progress.Children.Add(measurementStatus);
        var measurementStatusStyle = new Style(typeof(TextBlock));
        var emptyStatus = new Trigger {Property = TextBlock.TextProperty, Value = ""};
        emptyStatus.Setters.Add(new Setter(VisibilityProperty, Visibility.Collapsed));
        measurementStatusStyle.Triggers.Add(emptyStatus);
        measurementStatus.Style = measurementStatusStyle;
        footer.Children.Add(new ScrollViewer
        {
            Content = progress,
            MaxHeight = 54,
            Margin = new Thickness(14, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        });
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(pages);
        Content = root;
        start.Click += async (_, _) => await Run();
        stop.Click += (_, _) => Cancel();
        Closed += (_, _) => Cancel();
    }

    private static ScrollViewer PageBody(FrameworkElement content)
    {
        content.Margin = new Thickness(12, 8, 12, 4);
        return new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            PanningMode = PanningMode.VerticalOnly,
            Content = content
        };
    }

    private static void AddField(Panel panel, string label, FrameworkElement field)
    {
        panel.Children.Add(new Label {Content = label, Target = field, Padding = new Thickness(0, 0, 0, 4)});
        field.Margin = new Thickness(0, 0, 0, 4);
        panel.Children.Add(field);
    }

    private static void AddSetting(Panel panel, string label, TextBox field)
    {
        var row = new DockPanel {Margin = new Thickness(0, 0, 0, 6)};
        field.Width = 76;
        DockPanel.SetDock(field, Dock.Right);
        row.Children.Add(field);
        row.Children.Add(new Label
        {
            Content = new TextBlock {Text = label, TextWrapping = TextWrapping.Wrap},
            Target = field,
            Padding = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center
        });
        panel.Children.Add(row);
    }

    private void AddResult(string step, string status, string detail)
    {
        step = StepName(step);
        status = status switch {
            "ok" => "успешно", "failed" => "ошибка", "unavailable" => "нет данных",
            "warning" => "предупреждение",
            "unconfirmed" => "не подтверждено", "skipped" => "пропущено",
            "interrupted" => "прервано", "cancelled" => "остановлено", "info" => "сведения", _ => status };
        resultHint.Visibility = Visibility.Collapsed;
        report.AppendLine($"{step}: {status}").AppendLine(detail).AppendLine();
        observations.Children.Add(new Expander {Header = $"{step}: {status}", IsExpanded = status is "ошибка" or "не подтверждено" or "нет данных" or "прервано" or "предупреждение", Margin = new Thickness(0, 3, 0, 3),
            Content = new TextBox {Text = detail, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, BorderThickness = new Thickness(0), Background = System.Windows.Media.Brushes.Transparent}});
    }

    private string StepName(string key) => key switch {
        "tcp_connect" => "Подключение TCP", "tls" => "Проверка TLS", "route_confirmation" => "Регистрация процесса",
        "control" => "Управляющий канал", "server_observations" => "Наблюдения сервера", "client_observations" => "Наблюдения Windows",
        "server_network" => "Сеть сервера",
        "mss_first_leg" => "MSS до сервера", "mss_stun" => "MSS до внешнего узла", "speed_node" => "Узел M-Lab",
        "speed_download" => "Загрузка", "speed_upload" => "Отдача", "session" => "Сеанс", "process" => "Процесс",
        _ => steps.FirstOrDefault(item => item.key == key).check?.Content?.ToString() ?? key };

    private async Task Run()
    {
        var selected = steps.Where(x => x.check.IsEnabled && x.check.IsChecked == true).Select(x => x.key)
            .OrderBy(step => step != "direct_ping").ToArray();
        if (selected.Length == 0) return;
        int target = 0;
        if (selected.Any(step => step != "direct_ping") && mode.SelectedIndex == 1 &&
            !string.IsNullOrWhiteSpace(pid.Text) && (!int.TryParse(pid.Text, out target) || target < 0))
        {MessageBox.Show(this, "Проверьте PID.", Title); return;}
        int seconds = 60, bytes = 64, repeats = 1, pingDuration = 60, directPingDuration = 10;
        if ((selected.Contains("load") && (!int.TryParse(loadSeconds.Text, out seconds) || seconds is < 1 or > 300 ||
            !int.TryParse(loadBytes.Text, out bytes) || bytes is < 32 or > 1200 ||
            !int.TryParse(loadRepeats.Text, out repeats) || repeats is < 1 or > 5)) ||
            (selected.Contains("ping") && !selected.Contains("load") && (!int.TryParse(pingSeconds.Text, out pingDuration) || pingDuration is < 1 or > 3600)) ||
            (selected.Contains("direct_ping") && (!int.TryParse(directPingSeconds.Text, out directPingDuration) || directPingDuration is < 1 or > 3600))) {
            MessageBox.Show(this, "Проверьте параметры нагрузки и UDP-пинга.", Title); return;
        }
        var speed = selected.Contains("speed");
        if (speed && MessageBox.Show(this, "M-Lab публикует результаты измерений и собирает видимый выходной IP-адрес. Тест создаёт интенсивный трафик одного TCP-потока в каждом направлении. Продолжить?", "Скорость M-Lab NDT7", MessageBoxButton.YesNo, MessageBoxImage.Information) != MessageBoxResult.Yes) return;
        mode.IsEnabled = false; pid.IsEnabled = false;
        cancellation = new CancellationTokenSource(); start.IsEnabled = false; stop.IsEnabled = true;
        foreach (var item in steps) item.check.IsEnabled = false;
        measurementSettings.IsEnabled = false; measurementStatus.Text = "";
        observations.Children.Clear(); report.Clear(); report.AppendLine($"MIGA diagnostics {DateTimeOffset.Now:O}; server={server}");
        resultHint.Text = "Результаты появятся по мере завершения проверок.";
        resultHint.Visibility = Visibility.Visible;
        pages.SelectedItem = resultsPage;
        try
        {
            var executable = Path.Combine(AppContext.BaseDirectory, "miga_diagnostics.exe");
            if (!File.Exists(executable)) throw new FileNotFoundException("Не найден диагностический процесс miga_diagnostics.exe рядом с Agent.");
            helper = new Process {StartInfo = new ProcessStartInfo(executable) {UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardInputEncoding = new UTF8Encoding(false)}};
            if (!helper.Start()) throw new IOException("Не удалось запустить диагностический процесс.");
            var stderr = helper.StandardError.ReadToEndAsync(cancellation.Token);
            var config = new JsonObject {["server"] = server, ["profile_id"] = profileId, ["mode"] = mode.SelectedIndex == 0 ? "tunnel" : "rules", ["target_pid"] = target, ["speed_consent"] = speed,
                ["load_seconds"] = seconds, ["load_bytes"] = bytes, ["load_repeats"] = repeats, ["load_rates"] = loadRates.Text, ["ping_seconds"] = pingDuration,
                ["direct_ping_seconds"] = directPingDuration,
                ["steps"] = new JsonArray(selected.Select(x => JsonValue.Create(x)).ToArray<JsonNode?>())};
            await helper.StandardInput.WriteLineAsync(config.ToJsonString());
            while (await helper.StandardOutput.ReadLineAsync(cancellation.Token) is { } line)
            {
                var message = JsonNode.Parse(line)!.AsObject();
                switch (message["kind"]?.GetValue<string>())
                {
                    case "progress":
                        var step = message["step"]!.GetValue<string>();
                        current.Text = $"Шаг {Array.IndexOf(selected, step) + 1} из {selected.Length} · {StepName(step)}";
                        break;
                    case "result":
                        AddResult(message["step"]!.GetValue<string>(), message["status"]!.GetValue<string>(), message["detail"]!.GetValue<string>());
                        if (message["series"] is JsonArray series) AddPingGraph(series);
                        break;
                    case "load_progress": current.Text = message["detail"]!.GetValue<string>(); break;
                    case "ping_progress": measurementStatus.Text = message["detail"]!.GetValue<string>(); break;
                    case "control":
                        JsonObject response;
                        try {response = await Control(message["request"]!.AsObject(), cancellation.Token);}
                        catch (Exception error) {CloseControl(); response = new JsonObject {["ok"] = false, ["error"] = error.Message};}
                        await helper.StandardInput.WriteLineAsync(new JsonObject {["id"] = message["id"]!.DeepClone(), ["response"] = response}.ToJsonString()); break;
                }
            }
            await helper.WaitForExitAsync(cancellation.Token);
            var errors = await stderr;
            if (errors.Length > 0) AddResult("process", "info", errors);
            current.Text = helper.ExitCode == 0 ? "Сеанс завершён" : "Сеанс завершён с ошибкой";
        }
        catch (OperationCanceledException) {current.Text = "Сеанс остановлен"; AddResult("session", "cancelled", "Сохранён частичный отчёт. Временный маршрут снят при закрытии диагностического процесса.");}
        catch (Exception error) {current.Text = "Ошибка сеанса"; AddResult("session", "failed", error.Message);}
        finally
        {
            StopHelper();
            helper?.Dispose(); helper = null; CloseControl(); cancellation.Dispose(); cancellation = null;
            start.IsEnabled = true; stop.IsEnabled = false; measurementSettings.IsEnabled = true;
            mode.IsEnabled = true; pid.IsEnabled = true;
            updateMode();
        }
    }

    private void AddPingGraph(JsonArray series)
    {
        var canvas = new Canvas {Height = 150, Margin = new Thickness(10), ClipToBounds = true};
        canvas.SizeChanged += (_, _) => {
            canvas.Children.Clear();
            if (series.Count == 0 || canvas.ActualWidth <= 0) return;
            var maximum = Math.Max(1, series.Max(x => x?["rtt"]?.GetValue<double>() ?? 0));
            var duration = Math.Max(1, series[^1]!["second"]!.GetValue<double>());
            canvas.Children.Add(new TextBlock {Text = $"0–{maximum:F1} мс · 0–{duration:F0} с", Foreground = System.Windows.Media.Brushes.Gray});
            var stride = Math.Max(1, series.Count / 1000);
            var line = new System.Windows.Shapes.Polyline {Stroke = System.Windows.Media.Brushes.DeepSkyBlue, StrokeThickness = 1.5};
            canvas.Children.Add(line);
            for (int i = 0; i < series.Count; i += stride) {
                var item = series[i]!; var x = item["second"]!.GetValue<double>() / duration * canvas.ActualWidth;
                if (item["rtt"] is JsonValue rtt) line.Points.Add(new Point(x, 140 - rtt.GetValue<double>() / maximum * 130));
                else {
                    canvas.Children.Add(new System.Windows.Shapes.Line {X1 = x, X2 = x, Y1 = 135, Y2 = 145, Stroke = System.Windows.Media.Brushes.OrangeRed, StrokeThickness = 2});
                    line = new System.Windows.Shapes.Polyline {Stroke = System.Windows.Media.Brushes.DeepSkyBlue, StrokeThickness = 1.5}; canvas.Children.Add(line);
                }
            }
        };
        observations.Children.Add(new Expander {Header = "UDP RTT во времени: синий — ответы, красный — нет ответа", IsExpanded = true, Content = canvas});
    }

    private async Task<JsonObject> Control(JsonObject request, CancellationToken cancellation)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(15));
        if (tls == null)
        {
            if (string.IsNullOrEmpty(profileId)) throw new IOException("Добавьте приглашение для серверных проверок. Локальные проверки доступны.");
            var parameters = await new ProtocolV2ProfileService().OpenDiagnosticsAsync(profileId, timeout.Token);
            var host = parameters["host"]!.GetValue<string>();
            var fingerprint = parameters["fingerprint"]!.GetValue<string>();
            tcp = new TcpClient(AddressFamily.InterNetwork);
            await tcp.ConnectAsync(host, parameters["port"]!.GetValue<int>(), timeout.Token);
            tls = new SslStream(tcp.GetStream(), false, (_, certificate, _, _) =>
                certificate != null && DiagnosticAuthorization.MatchesCertificate(certificate.GetRawCertData(), fingerprint));
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {TargetHost = host}, timeout.Token);
            controlReader = new StreamReader(tls, Encoding.UTF8, false, 4096, true);
            controlWriter = new StreamWriter(tls, new UTF8Encoding(false), 4096, true) {AutoFlush = true};
            await controlWriter.WriteLineAsync(new JsonObject {["command"] = "authorize", ["ticket"] = parameters["ticket"]!.DeepClone()}.ToJsonString().AsMemory(), timeout.Token);
            var authorization = await controlReader.ReadLineAsync(timeout.Token);
            if (authorization == null || JsonNode.Parse(authorization)?["ok"]?.GetValue<bool>() != true)
                throw new IOException("Сервер отклонил одноразовый доступ диагностики. Повторите запуск после подключения.");
        }
        await controlWriter!.WriteLineAsync(request.ToJsonString().AsMemory(), timeout.Token);
        var response = await controlReader!.ReadLineAsync(timeout.Token) ?? throw new IOException("Сервер закрыл TLS-сеанс.");
        if (response.Length > 1024 * 1024) throw new IOException("Превышен размер серверного ответа.");
        return JsonNode.Parse(response)!.AsObject();
    }

    private void CloseControl()
    {
        foreach (var resource in new IDisposable?[] {controlWriter, controlReader, tls, tcp})
            try {resource?.Dispose();} catch (IOException) {} catch (ObjectDisposedException) {}
        controlWriter = null; controlReader = null; tls = null; tcp = null;
    }

    private void StopHelper()
    {
        try {if (helper is {HasExited: false}) helper.Kill(true);}
        catch (InvalidOperationException) {}
    }

    private void Cancel()
    {
        cancellation?.Cancel();
        StopHelper();
        CloseControl();
    }
}
