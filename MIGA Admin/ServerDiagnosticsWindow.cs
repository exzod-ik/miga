using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using MIGA_Agent.Services;

namespace MIGA_Agent.Views.Dialogs;

internal sealed class ServerDiagnosticsWindow : Window
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);
    private const string SynchronizeCommand = """
        run_admin() {
            if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n -- "$@"; fi
        }
        if systemctl is-active --quiet chrony.service chronyd.service; then
            run_admin chronyc makestep 0.1 1 && run_admin chronyc burst 1/2
        elif systemctl is-active --quiet systemd-timesyncd.service; then
            run_admin systemctl restart systemd-timesyncd.service
        else
            ntp=$(timedatectl show --property=NTP --value) || exit 1
            case "$ntp" in
                no) run_admin timedatectl --no-ask-password set-ntp true ;;
                yes) printf '%s\n' '{"error":"unsupported_time_service"}'; exit 1 ;;
                *) exit 1 ;;
            esac
        fi
        """;

    private readonly ISshManager _sshManager;
    private readonly string _host;
    private readonly TextBox _udpPort = new() { Text = "0", Width = 72, VerticalContentAlignment = VerticalAlignment.Center };
    private readonly TextBlock _udpStatus = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Button _udpStart = new() { Content = "Проверить UDP", Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(8, 0, 0, 0) };
    private readonly Button _udpCancel = new() { Content = "Отменить", IsEnabled = false, Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(8, 0, 0, 0) };
    private CancellationTokenSource? _udpCancellation;
    private bool _closeAfterUdp;
    private readonly TextBlock _clock = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _ntp = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _operation = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Button _refresh = new() { Content = "Проверить время", Padding = new Thickness(12, 5, 12, 5) };
    private readonly Button _synchronize = new() { Content = "Синхронизировать по NTP", Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(8, 0, 0, 0) };

    public ServerDiagnosticsWindow(ISshManager sshManager, string host)
    {
        _sshManager = sshManager;
        _host = host;
        Title = $"Диагностика сервера — {host}";
        Width = 780;
        Height = 530;
        MinWidth = 620;
        MinHeight = 460;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var report = new TextBox
        {
            IsReadOnly = true,
            Padding = new Thickness(10, 6, 10, 6),
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        var actions = new WrapPanel { Margin = new Thickness(0, 8, 0, 4) };
        actions.Children.Add(_refresh);
        actions.Children.Add(_synchronize);
        var timePanel = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
        timePanel.Children.Add(new TextBlock { Text = "Время сервера", FontWeight = FontWeights.SemiBold });
        timePanel.Children.Add(_clock);
        timePanel.Children.Add(_ntp);
        timePanel.Children.Add(actions);
        timePanel.Children.Add(_operation);
        var layout = new Grid { Margin = new Thickness(16) };
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition());
        layout.Children.Add(timePanel);
        var udpPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
        udpPanel.Children.Add(new TextBlock { Text = "Проверка UDP в обоих направлениях", FontWeight = FontWeights.SemiBold });
        var udpActions = new WrapPanel { Margin = new Thickness(0, 4, 0, 4) };
        udpActions.Children.Add(new Label { Content = "UDP-порт (0 — автоматически)", Target = _udpPort, VerticalAlignment = VerticalAlignment.Center });
        udpActions.Children.Add(_udpPort);
        udpActions.Children.Add(_udpStart);
        udpActions.Children.Add(_udpCancel);
        udpPanel.Children.Add(udpActions);
        udpPanel.Children.Add(_udpStatus);
        Grid.SetRow(udpPanel, 1);
        layout.Children.Add(udpPanel);
        Grid.SetRow(report, 2);
        layout.Children.Add(report);
        Content = layout;

        _udpStart.Click += async (_, _) => await RunUdpCheckAsync();
        _udpCancel.Click += (_, _) => CancelUdp();
        _refresh.Click += async (_, _) => await RunTimeCheckAsync(false);
        _synchronize.Click += async (_, _) =>
        {
            if (MessageBox.Show(this, "Запустить синхронизацию по NTP? Время сервера может измениться скачком.",
                    "Синхронизация времени", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes)
                await RunTimeCheckAsync(true);
        };
        ContentRendered += async (_, _) =>
        {
            await RunTimeCheckAsync(false);
            try
            {
                report.Text = await _sshManager.ExecuteCheckedAsync(
                    "printf 'Версия miga_server: '; timeout -k 1s 3s /usr/local/miga_server --version 2>/dev/null || printf 'недоступна\\n'; " +
                    "systemctl show miga_server --property=ActiveState,SubState,MainPID && ip -4 address show && ip -4 route show && ss -lun && miga-server settings get --json",
                    CommandTimeout);
            }
            catch (Exception error)
            {
                report.Text = $"Не удалось собрать отчёт сервера. {SshCommandErrors.UserMessage(error)}";
            }
        };
        Closing += (_, args) =>
        {
            if (_udpCancellation is null)
            {
                args.Cancel = !_refresh.IsEnabled;
                return;
            }

            args.Cancel = true;
            _closeAfterUdp = true;
            CancelUdp();
        };
    }

    private void CancelUdp()
    {
        _udpCancel.IsEnabled = false;
        _udpStatus.Text = "UDP-проверка отменяется…";
        _udpCancellation?.Cancel();
    }

    private async Task RunUdpCheckAsync()
    {
        if (!_sshManager.IsConnected)
        {
            _udpStatus.Text = "Подключитесь к серверу по SSH.";
            return;
        }
        if (!ushort.TryParse(_udpPort.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) ||
            port is > 0 and < 1024)
        {
            _udpStatus.Text = "Укажите 0 для автоматического выбора или UDP-порт от 1024 до 65535.";
            return;
        }

        using var cancellation = new CancellationTokenSource();
        _udpCancellation = cancellation;
        _udpPort.IsEnabled = _udpStart.IsEnabled = _refresh.IsEnabled = _synchronize.IsEnabled = false;
        _udpCancel.IsEnabled = true;
        _udpStatus.Text = "Запускается временная UDP-проверка…";
        try
        {
            var result = await ServerUdpProbe.CheckAsync(_sshManager, _host, port, cancellation.Token);
            var outgoing = $"Admin → VPS: доставлено {result.ServerReceived} из {result.ClientSent} отправленных.";
            var incoming = result.ServerReceived == 0
                ? "VPS → Admin: проверка не состоялась, VPS не получил адрес клиента."
                : $"VPS → Admin: доставлено {result.ClientReceived} из {result.ServerSent} отправленных.";
            _udpStatus.Text = $"{result.Address}:{result.Port}\n{outgoing}\n{incoming}";
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            _udpStatus.Text = "UDP-проверка отменена.";
        }
        catch (ServerUdpProbe.ProbeException error)
        {
            _udpStatus.Text = error.Message;
        }
        catch (SocketException error)
        {
            _udpStatus.Text = $"Ошибка UDP ({error.SocketErrorCode}).";
        }
        catch (Exception error)
        {
            _udpStatus.Text = $"Не удалось проверить UDP. {SshCommandErrors.UserMessage(error)}";
        }
        finally
        {
            _udpCancellation = null;
            _udpCancel.IsEnabled = false;
            _udpPort.IsEnabled = _udpStart.IsEnabled = _refresh.IsEnabled = _synchronize.IsEnabled = true;
            if (_closeAfterUdp) Close();
        }
    }

    private async Task RunTimeCheckAsync(bool synchronize)
    {
        _refresh.IsEnabled = _synchronize.IsEnabled = _udpStart.IsEnabled = false;
        _operation.Text = synchronize ? "Запускается синхронизация по NTP…" : "Проверяется время сервера…";
        try
        {
            string result = "";
            if (synchronize)
            {
                try
                {
                    await _sshManager.ExecuteCheckedAsync(SynchronizeCommand.ReplaceLineEndings("\n"), CommandTimeout);
                    result = "Служба NTP приняла запрос на синхронизацию.";
                    await Task.Delay(TimeSpan.FromSeconds(2));
                }
                catch (Exception error)
                {
                    result = $"Не удалось запустить синхронизацию. {SshCommandErrors.UserMessage(error)}";
                }
            }

            await ReadClockAsync();
            await ReadNtpStatusAsync();
            _operation.Text = result;
        }
        finally
        {
            _refresh.IsEnabled = _synchronize.IsEnabled = _udpStart.IsEnabled = true;
        }
    }

    private async Task ReadClockAsync()
    {
        try
        {
            long started = Stopwatch.GetTimestamp();
            DateTimeOffset localStart = DateTimeOffset.UtcNow;
            string response = await _sshManager.ExecuteCheckedAsync("LC_ALL=C date -u '+%s %N'", CommandTimeout);
            TimeSpan roundTrip = Stopwatch.GetElapsedTime(started);
            string[] fields = response.Trim().Split(' ');
            if (fields.Length != 2 ||
                !long.TryParse(fields[0], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long seconds) ||
                fields[1].Length != 9 ||
                !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out int nanoseconds))
            {
                _clock.Text = "Сервер вернул время в неподдерживаемом формате.";
                return;
            }

            DateTimeOffset remoteTime = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(nanoseconds / 100);
            TimeSpan halfTrip = roundTrip / 2;
            DateTimeOffset localTime = localStart + halfTrip;
            double offset = (remoteTime - localTime).TotalMilliseconds;
            _clock.Text = FormattableString.Invariant($"Сервер {remoteTime:yyyy-MM-dd HH:mm:ss.fff} UTC\nWindows {localTime:yyyy-MM-dd HH:mm:ss.fff} UTC\n") +
                $"Сервер − Windows {offset:+0.0;-0.0;0.0} мс (оценка ±{halfTrip.TotalMilliseconds:0.0} мс)";
        }
        catch (ArgumentOutOfRangeException)
        {
            _clock.Text = "Сервер вернул время вне допустимого диапазона.";
        }
        catch (Exception error)
        {
            _clock.Text = $"Не удалось прочитать время сервера. {SshCommandErrors.UserMessage(error)}";
        }
    }

    private async Task ReadNtpStatusAsync()
    {
        try
        {
            string response = await _sshManager.ExecuteCheckedAsync(
                "timedatectl show --property=NTP --property=NTPSynchronized", CommandTimeout);
            string[] properties = response.Split('\n', StringSplitOptions.TrimEntries);
            string service = properties.Contains("NTP=yes") ? "включена" : properties.Contains("NTP=no") ? "выключена" : "неизвестно";
            string clock = properties.Contains("NTPSynchronized=yes") ? "подтверждена" :
                properties.Contains("NTPSynchronized=no") ? "не подтверждена" : "неизвестно";
            _ntp.Text = $"Служба NTP — {service}. Синхронизация часов — {clock}.";
        }
        catch (Exception error)
        {
            _ntp.Text = $"Статус NTP недоступен. {SshCommandErrors.UserMessage(error)}";
        }
    }
}
