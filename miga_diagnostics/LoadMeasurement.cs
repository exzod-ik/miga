using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Miga.Diagnostics;

public sealed record LoadSettings(int Seconds, int Bytes, int Repeats, int[] Rates)
{
    public static LoadSettings Parse(JsonObject config)
    {
        var seconds = config["load_seconds"]?.GetValue<int>() ?? 60;
        var bytes = config["load_bytes"]?.GetValue<int>() ?? 64;
        var repeats = config["load_repeats"]?.GetValue<int>() ?? 1;
        var rates = (config["load_rates"]?.GetValue<string>() ?? "100,250,500,1000,1500,2000")
            .Split(',', StringSplitOptions.TrimEntries).Select(int.Parse).ToArray();
        if (seconds is < 1 or > 300 || bytes is < 32 or > 1200 || repeats is < 1 or > 5 || rates.Length is < 1 or > 12 ||
            rates.Any(x => x is < 1 or > 10000) || !rates.SequenceEqual(rates.Order().Distinct()) ||
            (long)(seconds + 15) * rates.Length * repeats * 2 > 5400)
            throw new ArgumentException("Нагрузка: ступень 1–300 с, UDP payload 32–1200 байт, 1–5 повторов; возрастающие ступени 1–10000 пакетов/с. Общая длительность — до 90 минут.");
        return new(seconds, bytes, repeats, rates);
    }
}

public sealed class ProbeCounter
{
    private readonly object gate = new();
    private readonly bool[] seen;
    private readonly long[] seconds;
    private readonly int rate;
    private long unique, duplicates, reordered, errors;
    private int high = -1;
    public ProbeCounter(int rate, int duration) { this.rate = rate; seen = new bool[rate * duration]; seconds = new long[duration]; }
    public void Record(int sequence, bool success = true)
    {
        lock (gate)
        {
            if (sequence < 0 || sequence >= seen.Length) return;
            if (!success) { errors++; return; }
            if (seen[sequence]) { duplicates++; return; }
            seen[sequence] = true; unique++; seconds[sequence / rate]++;
            if (sequence < high) reordered++; else high = sequence;
        }
    }
    public JsonObject Snapshot()
    {
        lock (gate) return new JsonObject { ["unique"] = unique, ["duplicates"] = duplicates, ["reordered"] = reordered,
            ["errors"] = errors, ["seconds"] = new JsonArray(seconds.Select(x => JsonValue.Create(x)).ToArray<JsonNode?>()) };
    }
}

public static class LoadProbe
{
    public static byte[] Create(ulong run, uint step, byte direction, int bytes)
    {
        var data = RandomNumberGenerator.GetBytes(bytes);
        "MGL2"u8.CopyTo(data); BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(4), run);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), step); data[20] = direction;
        return data;
    }
    public static int Read(ReadOnlySpan<byte> data, ulong run, uint step, byte direction)
    {
        if (data.Length < 32 || !data[..4].SequenceEqual("MGL2"u8) || BinaryPrimitives.ReadUInt64BigEndian(data[4..]) != run ||
            BinaryPrimitives.ReadUInt32BigEndian(data[12..]) != step || data[20] != direction) return -1;
        var sequence = BinaryPrimitives.ReadUInt32BigEndian(data[16..]);
        return sequence <= int.MaxValue ? (int)sequence : -1;
    }
}

public sealed partial class DiagnosticRunner
{
    private async Task Load()
    {
        var settings = LoadSettings.Parse(config);
        using var pingStop = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var withPing = config["steps"]!.AsArray().Any(x => x!.GetValue<string>() == "ping");
        var pingTask = withPing ? Ping(TimeSpan.FromMinutes(95), pingStop.Token) : Task.CompletedTask;
        var run = BinaryPrimitives.ReadUInt64BigEndian(RandomNumberGenerator.GetBytes(8));
        if (run == 0) run = 1;
        uint step = 0;
        try
        {
            for (int repeat = 1; repeat <= settings.Repeats; repeat++)
                foreach (byte direction in new byte[] { 0, 1 })
                    foreach (int rate in settings.Rates)
                        await LoadStep(settings, run, ++step, direction, rate, repeat);
        }
        finally { pingStop.Cancel(); await pingTask; }
    }

    private async Task LoadStep(LoadSettings settings, ulong run, uint step, byte direction, int rate, int repeat)
    {
        using var socket = await Bind(17);
        socket.ReceiveBufferSize = 4 * 1024 * 1024;
        var parameters = new JsonObject { ["command"] = "load_prepare", ["run"] = run.ToString("x16"), ["step"] = step,
            ["direction"] = direction, ["rate"] = rate, ["seconds"] = settings.Seconds, ["bytes"] = settings.Bytes,
            ["local_port"] = ((IPEndPoint)socket.LocalEndPoint!).Port };
        var localParameters = (JsonObject)parameters.DeepClone(); localParameters["command"] = "load_configure";
        var sent = new ProbeCounter(rate, settings.Seconds); var received = new ProbeCounter(rate, settings.Seconds);
        long late = 0; double elapsed = 0;
        using var stopReceiver = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        Task receiveTask = Task.CompletedTask;
        JsonObject? before = null;
        try
        {
            var server = await Control(parameters);
            if (server["ok"]?.GetValue<bool>() != true) throw new IOException("Сервер не подготовил нагрузочный сокет: " + Text(server, "error"));
            if ((await Local(localParameters))["ok"]?.GetValue<bool>() != true) throw new IOException("Клиент не подготовил счётчики нагрузки.");
            var endpoint = new IPEndPoint(IPAddress.Parse(Text(server, "ip")), server["port"]!.GetValue<int>());
            var hello = LoadProbe.Create(run, step, 2, 32);
            BinaryPrimitives.WriteInt32BigEndian(hello.AsSpan(16), 0);
            bool ready = false;
            for (int attempt = 0; attempt < 3 && !ready; attempt++)
                ready = (await Datagram(socket, endpoint, hello, data => LoadProbe.Read(data.Span, run, step, 2) == 0)).success;
            if (!ready) throw new IOException("Проба через TUN не дошла до UDP-приложения сервера или ответ не вернулся. Нагрузка не запущена.");
            before = await Control(new JsonObject { ["command"] = "network_stats" });
            receiveTask = ReceiveLoad(socket, endpoint, run, step, direction, received, stopReceiver.Token);
            var clock = Stopwatch.StartNew();
            if (direction == 1)
            {
                if ((await Control(new JsonObject { ["command"] = "load_start" }))["ok"]?.GetValue<bool>() != true) throw new IOException("Сервер не подтвердил запуск отправки.");
                for (int second = 0; second < settings.Seconds; second++)
                {
                    await Task.Delay(1000, cancellation);
                    Program.Output(new { kind = "load_progress", detail = $"сервер → Windows · повтор {repeat} · {rate} пак/с · {second + 1}/{settings.Seconds} с · получено {received.Snapshot()["unique"]}" });
                }
            }
            else
            {
                var data = LoadProbe.Create(run, step, direction, settings.Bytes);
                int printed = -1;
                for (int sequence = 0; sequence < rate * settings.Seconds; sequence++)
                {
                    cancellation.ThrowIfCancellationRequested();
                    var due = (double)sequence / rate;
                    var delay = due - clock.Elapsed.TotalSeconds;
                    if (delay > 0) await Task.Delay(TimeSpan.FromSeconds(delay), cancellation);
                    if (clock.Elapsed.TotalSeconds >= settings.Seconds) break;
                    if (clock.Elapsed.TotalSeconds - due > .01) late++;
                    BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(16), sequence);
                    try { sent.Record(sequence, await socket.SendToAsync(data, SocketFlags.None, endpoint, cancellation) == data.Length); }
                    catch (SocketException) { sent.Record(sequence, false); }
                    var second = (int)clock.Elapsed.TotalSeconds;
                    if (second != printed) { printed = second; Program.Output(new { kind = "load_progress", detail = $"Windows → сервер · повтор {repeat} · {rate} пак/с · {second}/{settings.Seconds} с · отправлено {sent.Snapshot()["unique"]}" }); }
                }
            }
            elapsed = clock.Elapsed.TotalSeconds;
            await Task.Delay(5000, cancellation);
            JsonObject remote = new(), local = new();
            JsonObject application = received.Snapshot();
            string? previousSnapshot = null;
            bool stable = false;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                remote = await Control(new JsonObject { ["command"] = "load_stats" });
                local = await Local(new JsonObject { ["command"] = "load_stats" });
                if (remote["ok"]?.GetValue<bool>() != true || local["ok"]?.GetValue<bool>() != true) throw new IOException("Не получен согласованный снимок счётчиков ступени.");
                application = received.Snapshot();
                var snapshot = remote["stages"]!.ToJsonString() + local["stages"]!.ToJsonString() + application.ToJsonString();
                if (snapshot == previousSnapshot) { stable = true; break; }
                previousSnapshot = snapshot;
                await Task.Delay(500, cancellation);
            }
            stopReceiver.Cancel(); await receiveTask;
            stable &= application.ToJsonString() == received.Snapshot().ToJsonString();
            var stages = new List<(string Name, JsonNode Data)>();
            void Add(string name, JsonObject source, string key) => stages.Add((name, source["stages"]?[key] ?? throw new IOException("Нет счётчика " + key)));
            if (direction == 0)
            {
                stages.Add(("Приложение Windows отправило", sent.Snapshot()));
                Add("Клиент MIGA перехватил", local, "captured"); Add("Клиент выбрал туннель", local, "selected");
                Add("WinDivert подтвердил отправку", local, "wire_sent"); Add("Сервер MIGA принял", remote, "server_received");
                Add("Сервер записал в TUN", remote, "tun_written"); Add("Приложение сервера получило", remote, "app_received");
            }
            else
            {
                Add("Приложение сервера отправило", remote, "app_sent"); Add("Сервер прочитал из TUN", remote, "tun_read");
                Add("UDP-сокет подтвердил отправку", remote, "wire_sent"); Add("Клиент MIGA принял", local, "client_received");
                Add("WinDivert подтвердил reinject", local, "reinject"); stages.Add(("Приложение Windows получило", application));
            }
            var detail = FormatLoad(stages, rate, settings, elapsed);
            detail += $"\nЗадержанных отправок >10 мс: {(direction == 0 ? late : remote["sender_late"]?.GetValue<long>() ?? 0)}. " +
                $"Drops принимающего сокета сервера: {remote["socket_drops"]}; SO_RCVBUF сервера: {remote["receive_buffer"]}; Windows: {socket.ReceiveBufferSize}.";
            var after = await Control(new JsonObject { ["command"] = "network_stats" });
            detail += "\n" + ServerNetworkReport.FormatInterval(before, after);
            detail += stable ? "\nСнимки всех этапов стабильны при повторной проверке." : "\nСчётчики продолжают меняться: окно доставки нестабильно, локализация потерь предварительная.";
            Result("load", stable ? "info" : "warning", $"{(direction == 0 ? "Windows → сервер" : "сервер → Windows")}, повтор {repeat}, ступень {step}, {run:x16}\n{detail}");
        }
        finally
        {
            stopReceiver.Cancel();
            try { await receiveTask; } catch (SocketException) { }
            try { await Control(new JsonObject { ["command"] = "load_stop" }); } catch { }
            try { await Local(new JsonObject { ["command"] = "load_stop" }); } catch { }
        }
    }

    private async Task ReceiveLoad(Socket socket, IPEndPoint endpoint, ulong run, uint step, byte direction, ProbeCounter counter, CancellationToken token)
    {
        var data = new byte[2048];
        try
        {
            while (!token.IsCancellationRequested)
            {
                var response = await socket.ReceiveFromAsync(data, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), token);
                if (response.RemoteEndPoint.Equals(endpoint)) counter.Record(LoadProbe.Read(data.AsSpan(0, response.ReceivedBytes), run, step, direction));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    public static string FormatLoad(IReadOnlyList<(string Name, JsonNode Data)> stages, int rate, LoadSettings settings, double elapsed)
    {
        var sent = stages[0].Data["unique"]!.GetValue<long>(); var last = stages[^1].Data["unique"]!.GetValue<long>();
        var text = new StringBuilder($"Задано {rate} пак/с × {settings.Seconds} с, payload {settings.Bytes} байт. Фактическая отправка: {sent / Math.Max(elapsed, .001):F1} пак/с.\n");
        text.AppendLine($"Скорость payload отправки/приёма: {sent * settings.Bytes * 8 / Math.Max(elapsed, .001) / 1000000:F3} / {last * settings.Bytes * 8 / Math.Max(elapsed, .001) / 1000000:F3} Мбит/с.");
        text.AppendLine("Этап | Уникальные | Разница с предыдущим | % от отправленных | Ошибки | Дубликаты | Перестановки");
        long previous = sent;
        foreach (var (name, data) in stages)
        {
            var count = data["unique"]!.GetValue<long>(); var gap = previous - count;
            text.AppendLine($"{name} | {count} | {gap} | {(sent == 0 ? 0 : 100.0 * gap / sent):F2}% | {data["errors"]} | {data["duplicates"]} | {data["reordered"]}"); previous = count;
        }
        text.AppendLine($"Итог: получено {last}/{sent}, потеряно {sent - last} ({(sent == 0 ? 0 : 100.0 * (sent - last) / sent):F2}%). Окно доставки после нагрузки: 5 с.");
        text.AppendLine("Секундные группы по номерам отправки (без зависимости от синхронизации часов):");
        text.AppendLine("Секунда | " + string.Join(" | ", stages.Select(x => x.Name)));
        for (int second = 0; second < settings.Seconds; second++)
            text.AppendLine($"{second + 1} | " + string.Join(" | ", stages.Select(x => x.Data["seconds"]?[second]?.ToString() ?? "0")));
        text.Append("Подтверждение API отправки не доказывает выход с сетевой карты. Отрицательная разница требует проверки полноты наблюдений.");
        return text.ToString();
    }
}
