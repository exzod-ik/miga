using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Miga.Diagnostics;

public static class Program
{
    public static async Task<int> Main()
    {
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(120));
        Console.CancelKeyPress += (_, e) => {e.Cancel = true; lifetime.Cancel();};
        try
        {
            var line = await Console.In.ReadLineAsync(lifetime.Token);
            if (line == null) return 1;
            var configuration = JsonNode.Parse(line)!.AsObject();
            await using var runner = new DiagnosticRunner(configuration, lifetime.Token);
            await runner.Run();
            return 0;
        }
        catch (OperationCanceledException) {Output(new {kind = "result", step = "session", status = "cancelled", detail = "Сеанс остановлен."}); return 2;}
        catch (Exception error) {Output(new {kind = "result", step = "session", status = "failed", detail = error.Message}); return 1;}
    }

    public static void Output(object value) => Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(value));
}

public sealed partial class DiagnosticRunner : IAsyncDisposable
{
    private readonly JsonObject config;
    private readonly CancellationToken cancellation;
    private readonly NamedPipeClientStream pipe;
    private StreamReader? reader;
    private StreamWriter? writer;
    private JsonObject prepared = new();
    private readonly SemaphoreSlim localGate = new(1, 1);
    private readonly SemaphoreSlim controlGate = new(1, 1);
    private int sequence;
    private int lastEchoSequence;
    private long lastStunWatch;
    private bool routeReady;
    private ulong? selectedServerId;
    private bool localOnly;
    private readonly bool rules;
    private readonly List<string> report = [];

    public DiagnosticRunner(JsonObject config, CancellationToken cancellation, string pipeName = "MigaDiagnostics-v1")
    {
        pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        this.config = config; this.cancellation = cancellation;
        rules = config["mode"]?.GetValue<string>() == "rules";
    }

    private static string Text(JsonNode? node, string key) => node?[key]?.GetValue<string>() ?? "";
    private void Result(string step, string status, string detail)
    {
        report.Add($"{step}: {status}\n{detail}");
        Program.Output(new {kind = "result", step, status, detail});
    }

    private async Task<JsonObject> Local(JsonObject command)
    {

        await localGate.WaitAsync(cancellation);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            await writer!.WriteLineAsync(command.ToJsonString().AsMemory(), timeout.Token);
            var line = await reader!.ReadLineAsync(timeout.Token) ?? throw new IOException("Служба закрыла канал диагностики.");
            return JsonNode.Parse(line)!.AsObject();
        }
        finally { localGate.Release(); }
    }

    private async Task<JsonObject> Control(JsonObject command)
    {

        await controlGate.WaitAsync(cancellation);
        try
        {
            var id = Interlocked.Increment(ref sequence);
            Program.Output(new {kind = "control", id, request = command});
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            var line = await Console.In.ReadLineAsync(timeout.Token) ?? throw new IOException("Agent закрыл управляющий канал.");
            var response = JsonNode.Parse(line)!.AsObject();
            if (response["id"]?.GetValue<int>() != id) throw new IOException("Нарушен порядок управляющих ответов.");
            return response["response"]!.AsObject();
        }
        finally { controlGate.Release(); }
    }

    public async Task Run()
    {
        var steps = config["steps"]!.AsArray().Select(x => x!.GetValue<string>()).ToArray();
        var directPing = steps.Contains("direct_ping");
        var otherSteps = steps.Where(step => step != "direct_ping").ToArray();
        if (directPing) Program.Output(new {kind = "progress", step = "direct_ping"});
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(5000);
            await pipe.ConnectAsync(timeout.Token);
            reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
            writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) {AutoFlush = true};
        }
        catch (Exception error) when (error is not OperationCanceledException || !cancellation.IsCancellationRequested)
        {
            if (directPing) Result("direct_ping", "unavailable", "Не удалось подключиться к локальной службе MIGA для подтверждения прямого маршрута.");
            if (otherSteps.Length > 0) Result("route_confirmation", "failed", error.Message);
        }

        if (directPing && writer != null)
        {
            try {await DirectPing(config["direct_ping_seconds"]?.GetValue<int>() ?? 10);}
            catch (Exception error) when (error is not OperationCanceledException || !cancellation.IsCancellationRequested)
            {Result("direct_ping", "failed", error.Message);}
        }

        if (otherSteps.Length > 0 && writer != null && pipe.IsConnected)
        try
        {
            var begin = new JsonObject { ["command"] = "begin", ["server"] = Text(config, "server"), ["mode"] = rules ? "rules" : "tunnel",
                ["profile_id"] = config["profile_id"]?.DeepClone() };
            if (config["target_pid"]?.GetValue<int>() is > 0) begin["target_pid"] = config["target_pid"]!.DeepClone();
            var response = await Local(begin);
            routeReady = response["ok"]?.GetValue<bool>() == true;
            selectedServerId = response["server_id"]?.GetValue<ulong>();
            localOnly = response["local_only"]?.GetValue<bool>() == true;
            Result("route_confirmation", routeReady ? "ok" : "failed", response.ToJsonString());
        }
        catch (Exception error) when (error is not OperationCanceledException || !cancellation.IsCancellationRequested)
        {Result("route_confirmation", "failed", error.Message);}

        if (!localOnly && routeReady && otherSteps.Any(step => step is not "capture" and not "route"))
        try {
            prepared = await Control(new JsonObject { ["command"] = "begin" });
            if (prepared["ok"]?.GetValue<bool>() != true)
                Result("control", "unavailable", Text(prepared, "error"));
        }
        catch (Exception error) when (error is not OperationCanceledException || !cancellation.IsCancellationRequested)
        {Result("control", "unavailable", $"Нет серверных наблюдений: {error.Message}");}

        foreach (var step in otherSteps)
        {
            cancellation.ThrowIfCancellationRequested();
            Program.Output(new {kind = "progress", step});
            if (!routeReady) {Result(step, "skipped", "Служба не подтвердила маршрут экземпляра процесса до открытия тестовых сокетов."); continue;}
            if (step is not "capture" and not "route" && (localOnly || prepared["ok"]?.GetValue<bool>() != true))
            {Result(step, "skipped", "Для серверной проверки требуется подключённая сессия и доступ к диагностике сервера."); continue;}
            if (rules && config["target_pid"]?.GetValue<int>() is > 0 && step is not "capture" and not "route")
            {Result(step, "skipped", "В режиме наблюдения приложения активные пробы отдельного процесса не проверяют его правило."); continue;}
            if (rules && step is "speed" or "load" or "ping")
            {Result(step, "skipped", "Для измерения через выбранный сервер включите режим проверки туннеля."); continue;}
            try
            {
                switch (step)
                {
                    case "capture": case "route": await Observe(step); break;
                    case "first_leg": await FirstLeg(); break;
                    case "tcp": await Tcp(); break;
                    case "udp": await Udp(); break;
                    case "mss": await Mss(); break;
                    case "speed": await Speed(); break;
                    case "load": await Load(); break;
                    case "ping":
                        if (!otherSteps.Contains("load")) {
                            var seconds = config["ping_seconds"]?.GetValue<int>() ?? 60;
                            if (seconds is < 1 or > 3600) throw new ArgumentException("Длительность UDP-пинга: 1–3600 секунд.");
                            await Ping(TimeSpan.FromSeconds(seconds), cancellation);
                        }
                        break;
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) {throw;}
            catch (Exception error) {Result(step, "failed", error.Message);}
            finally {
                if (!cancellation.IsCancellationRequested)
                    await Local(new JsonObject { ["command"] = "finish_step" });
            }
        }
        if (routeReady) Result("client_observations", "info", (await Local(new JsonObject {["command"] = "stats"})).ToJsonString());
        if (prepared["ok"]?.GetValue<bool>() == true)
        try {
            var stats = await Control(new JsonObject {["command"] = "stats"});
            Result("server_observations", stats["ok"]?.GetValue<bool>() == true ? "info" : "unavailable", stats.ToJsonString());
        }
        catch (Exception error) {Result("server_observations", "unavailable", error.Message);}
        if (prepared["ok"]?.GetValue<bool>() == true)
        {
            try
            {
                var network = ServerNetworkReport.Format(await Control(new JsonObject { ["command"] = "network_stats" }));
                Result("server_network", network.Status, network.Detail);
            }
            catch (Exception error) {Result("server_network", "unavailable", error.Message);}
        }
        Program.Output(new {kind = "complete", report = string.Join("\n\n", report)});
    }

    private async Task<Socket> Bind(int protocol)
    {
        var socket = new Socket(AddressFamily.InterNetwork, protocol == 6 ? SocketType.Stream : SocketType.Dgram, protocol == 6 ? ProtocolType.Tcp : ProtocolType.Udp);
        try
        {
            socket.ExclusiveAddressUse = true;
            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
            var response = await Local(new JsonObject {["command"] = "register", ["protocol"] = protocol, ["local_port"] = port});
            if (response["ok"]?.GetValue<bool>() != true) throw new IOException("Не подтверждена регистрация тестового сокета.");
            return socket;
        }
        catch {socket.Dispose(); throw;}
    }

    private async Task<long> Watch(Socket socket, string ip, int port, int protocol, string? transaction = null)
    {
        if (prepared["ok"]?.GetValue<bool>() != true) return 0;
        var response = await Control(new JsonObject {["command"] = "watch", ["protocol"] = protocol, ["local_port"] = ((IPEndPoint)socket.LocalEndPoint!).Port, ["remote_ip"] = ip, ["remote_port"] = port, ["transaction_id"] = transaction ?? ""});
        if (response["ok"]?.GetValue<bool>() != true) throw new IOException("Сервер не подтвердил наблюдение потока.");
        return response["watch_id"]!.GetValue<long>();
    }

    private async Task Observe(string step)
    {
        if (config["target_pid"]?.GetValue<int>() is > 0)
        {
            await BeginObservation(new JsonObject {["command"] = "observe_begin"});
            Result(step, "info", "Наблюдение соединений выбранного приложения в течение 5 секунд.");
            await Task.Delay(5000, cancellation);
        }
        else
        {
            var ip = Text(prepared, "stun_ip");
            var endpoint = ip.Length > 0 ? new IPEndPoint(IPAddress.Parse(ip), 3478) :
                new IPEndPoint(IPAddress.Parse("192.0.2.1"), 47901);
            using var socket = await Bind(17);
            await BeginObservation(new JsonObject {
                ["command"] = "observe_begin", ["protocol"] = 17,
                ["local_port"] = ((IPEndPoint)socket.LocalEndPoint!).Port,
                ["remote_ip"] = BinaryPrimitives.ReadUInt32BigEndian(endpoint.Address.GetAddressBytes()),
                ["remote_port"] = endpoint.Port
            });
            if (ip.Length > 0) await Stun(socket, ip, 48, false);
            else
            {
                await socket.SendToAsync(new byte[1], SocketFlags.None, endpoint, cancellation);
                await Task.Delay(500, cancellation);
            }
        }
        var stats = await Local(new JsonObject {["command"] = "observe_end"});
        if (stats["ok"]?.GetValue<bool>() != true) throw new IOException("Не удалось получить результаты наблюдения.");
        var captured = stats["captured"]?.GetValue<long>() ?? 0;
        var unowned = stats["unowned"]?.GetValue<long>() ?? 0;
        var details = new StringBuilder($"Пакеты с определённым владельцем: {captured}. Без владельца на зарегистрированных сокетах: {unowned}.");
        var flows = stats["flows"]?.AsArray() ?? [];
        foreach (var flow in flows)
        {
            var ip = flow!["remote_ip"]!.GetValue<uint>();
            var endpoint = $"{ip >> 24}.{(ip >> 16) & 255}.{(ip >> 8) & 255}.{ip & 255}:{flow["remote_port"]}";
            details.AppendLine().Append($"{flow["application"]} (PID {flow["pid"]}) → {endpoint}: {flow["route"]}, {flow["reason"]}");
            if (flow["route"]?.GetValue<string>() == "tunnel") details.Append($", ID сервера {flow["server_id"]}");
        }
        var confirmed = step == "capture" ? captured > 0 : flows.Any(flow => MatchesObservedRoute(flow, rules, selectedServerId));
        Result(step, confirmed ? "ok" : "unconfirmed", details.ToString());
    }

    private async Task BeginObservation(JsonObject request)
    {
        var response = await Local(request);
        if (response["ok"]?.GetValue<bool>() != true)
            throw new IOException("Служба не подтвердила начало наблюдения.");
    }

    internal static bool MatchesObservedRoute(JsonNode? flow, bool rules, ulong? selectedServerId)
    {
        var route = Text(flow, "route");
        if (rules) return route is "direct" or "tunnel" or "drop";
        return route == "tunnel" && selectedServerId is > 0 && flow?["server_id"]?.GetValue<ulong>() == selectedServerId;
    }

    private async Task FirstLeg()
    {
        if (Text(prepared, "token").Length != 32) {Result("first_leg", "skipped", "Ответчик серверу не подготовлен: нет управляющего сеанса."); return;}
        using var socket = await Bind(17);
        var results = new List<string>(); var replies = 0;
        for (var i = 0; i < 5; i++)
        {
            var result = await Echo(socket, 48, false);
            if (result.success) replies++;
            results.Add($"Проба {i + 1}: {(result.success ? "ответ" : "тайм-аут")}, {result.ms:F1} мс");
        }
        Result("first_leg", replies == 5 ? "ok" : "unconfirmed", $"Получено {replies}/5.\n{string.Join("\n", results)}\nЗавершения и приём на сервере приведены в наблюдениях сеанса.");
    }

    private async Task<(bool success, double ms)> Echo(Socket socket, int ipSize, bool df)
    {
        var payload = new byte[Math.Max(20, ipSize - 28)];
        Convert.FromHexString(Text(prepared, "token")).CopyTo(payload, 0);
        lastEchoSequence = Interlocked.Increment(ref sequence);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(16), lastEchoSequence);
        socket.DontFragment = df;
        var endpoint = new IPEndPoint(IPAddress.Parse(Text(prepared, "echo_ip")), prepared["echo_port"]!.GetValue<int>());
        return await Datagram(socket, endpoint, payload, data => data.Length >= 20 && data.Span[..20].SequenceEqual(payload.AsSpan(0, 20)));
    }

    private async Task<(bool success, double ms)> Stun(Socket socket, string ip, int ipSize, bool df)
    {
        var size = Math.Max(20, ipSize - 28);
        if (size > 20) size = Math.Max(24, (size + 3) & ~3);
        var request = CreateStunRequest(size);
        lastStunWatch = await Watch(socket, ip, 3478, 17, Convert.ToHexString(request.AsSpan(8, 12)));
        if (size > 20) {BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(20), 0x0026); BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(22), (ushort)(size - 24));}
        socket.DontFragment = df;
        var endpoint = new IPEndPoint(IPAddress.Parse(ip), 3478);
        return await Datagram(socket, endpoint, request, data => MatchesStunBinding(data.Span, request));
    }

    private async Task<(bool success, double ms)> Datagram(Socket socket, IPEndPoint endpoint, byte[] payload, Func<ReadOnlyMemory<byte>, bool> validate)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(2500);
        var clock = Stopwatch.StartNew();
        try
        {
            await socket.SendToAsync(payload, SocketFlags.None, endpoint, timeout.Token);
            var buffer = new byte[2048];
            while (true)
            {
                var response = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
                if (response.RemoteEndPoint.Equals(endpoint) && validate(buffer.AsMemory(0, response.ReceivedBytes))) return (true, clock.Elapsed.TotalMilliseconds);
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) {return (false, clock.Elapsed.TotalMilliseconds);}
        catch (SocketException error) when (error.SocketErrorCode is SocketError.MessageSize or SocketError.TimedOut or SocketError.ConnectionReset) {return (false, clock.Elapsed.TotalMilliseconds);}
    }

    private async Task Tcp()
    {
        var ip = Text(prepared, "tcp_ip"); var host = Text(prepared, "tcp_host");
        if (ip.Length == 0) {Result("tcp", "skipped", "Сервер не подготовил IPv4 внешнего сервиса."); return;}
        using var socket = await Bind(6); await Watch(socket, ip, 443, 6);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(8000);
        var clock = Stopwatch.StartNew();
        try {await socket.ConnectAsync(IPAddress.Parse(ip), 443, timeout.Token); Result("tcp_connect", "ok", $"{host} ({ip}:443), {clock.Elapsed.TotalMilliseconds:F1} мс");}
        catch (Exception error) {Result("tcp_connect", "failed", $"{ip}:443: {error.Message}"); Result("tls", "skipped", "TCP не установлен."); return;}
        using var stream = new NetworkStream(socket, false); using var tls = new SslStream(stream, false);
        clock.Restart();
        try {await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {TargetHost = host}, timeout.Token); Result("tls", "ok", $"Сертификат проверен по {host}, {tls.SslProtocol}, {clock.Elapsed.TotalMilliseconds:F1} мс");}
        catch (Exception error) {Result("tls", "failed", error.Message);}
    }

    private async Task Udp()
    {
        var ip = Text(prepared, "stun_ip");
        if (ip.Length == 0) {Result("udp", "skipped", "Ошибка подготовки IPv4 STUN на сервере."); return;}
        using var socket = await Bind(17);
        var result = await Stun(socket, ip, 48, false);
        Result("udp", result.success ? "ok" : "unconfirmed", $"stun.cloudflare.com ({ip}:3478), Binding Success Response {(result.success ? "получен с совпавшим transaction ID" : "не получен")}, {result.ms:F1} мс.");
        JsonObject stats;
        try { stats = await Control(new JsonObject {["command"] = "stats"}); }
        catch (Exception error) when (!cancellation.IsCancellationRequested) {
            Result("server_observations", "unavailable", error.Message);
            return;
        }
        var flow = stats["watches"]?.AsArray().FirstOrDefault(x => x?["watch_id"]?.GetValue<long>() == lastStunWatch);
        if (flow != null)
            Result("server_observations", "info", $"STUN: принято на сервере — {flow["received"]}, записано в TUN — {flow["tun_written"]}, ответов из TUN — {flow["tun_response"]}.");
    }

    private async Task Mss()
    {
        if (prepared["ok"]?.GetValue<bool>() != true) {Result("mss", "skipped", "Управляющий сеанс Сервер недоступен."); return;}
        foreach (var direction in new[] {"first_leg", "stun"})
        {
            using var socket = await Bind(17); var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
            var options = await Local(new JsonObject {["command"] = "options", ["mss"] = true, ["probe_port"] = port});
            if (options["ok"]?.GetValue<bool>() != true) throw new IOException("Служба не подтвердила режим DF для пробы.");
            try
            {
                var ip = Text(prepared, "stun_ip");
                if (direction == "stun" && ip.Length == 0) {Result("mss_stun", "skipped", "IPv4 STUN не подготовлен."); continue;}
                var confirmed = 0; int? unconfirmed = null; var interrupted = false; var observations = new List<string>();
                async Task<bool> Probe(int size)
                {
                    var result = direction == "first_leg" ? await Echo(socket, size, true) : await Stun(socket, ip, size, true);
                    var after = await Control(new JsonObject {["command"] = "stats"});
                    bool serverConfirmed = direction == "first_leg"
                        ? after["echo"]?["sequences"]?.AsArray().Any(x => x?["sequence"]?.GetValue<int>() == lastEchoSequence && x["ip_size"]?.GetValue<int>() == size) == true
                        : after["watches"]?.AsArray().Any(x => x?["watch_id"]?.GetValue<long>() == lastStunWatch &&
                            x["last_ip_size"]?.GetValue<int>() == size && x["inner_df"]?.GetValue<bool>() == true &&
                            x["tun_response"]?.GetValue<long>() > 0) == true;
                    var accepted = result.success || serverConfirmed;
                    observations.Add($"{size} байт IPv4: {(accepted ? "подтверждено" : "не подтверждено")}, ответ Windows={result.success}, {result.ms:F1} мс");
                    return accepted;
                }
                foreach (var size in new[] {48, 576, 1000, 1200, 1280, 1320, 1360, 1400, 1420, 1440, 1460, 1480, 1500})
                {
                    if (await Probe(size)) {confirmed = size; continue;}
                    unconfirmed = size;
                    if (await Probe(size)) {confirmed = size; unconfirmed = null; continue;}
                    if (confirmed == 0 || !await Probe(confirmed)) interrupted = true;
                    break;
                }
                Result($"mss_{direction}", interrupted ? "interrupted" : confirmed > 0 ? "ok" : "unconfirmed",
                    $"Исходящее направление {(direction == "first_leg" ? "Windows → сервер" : "Windows → Cloudflare STUN через сервер")}. Подтверждено IPv4 N={confirmed}; расчётный MSS={(confirmed >= 40 ? confirmed - 40 : 0)}. Неподтверждённый размер={unconfirmed?.ToString() ?? "нет"}.\n{string.Join("\n", observations)}\nКороткий ответ не измеряет обратное направление. Глобальная настройка не изменена.");
            }
            finally {await Local(new JsonObject {["command"] = "options", ["mss"] = false, ["probe_port"] = 0});}
        }
    }

    private async ValueTask<Stream> Connect(SocketsHttpConnectionContext context, CancellationToken token)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, AddressFamily.InterNetwork, token);
        if (addresses.Length == 0) throw new IOException("Нет IPv4 для узла NDT7.");
        var socket = await Bind(6);
        try {await socket.ConnectAsync(addresses[0], context.DnsEndPoint.Port, token); return new NetworkStream(socket, true);}
        catch {socket.Dispose(); throw;}
    }

    private async Task Speed()
    {
        if (config["speed_consent"]?.GetValue<bool>() != true) {Result("speed", "skipped", "Не подтверждена публикация измерений M-Lab и видимого выходного IP."); return;}
        using var handler = new SocketsHttpHandler {ConnectCallback = Connect, UseProxy = false};
        using var client = new HttpClient(handler) {Timeout = TimeSpan.FromSeconds(20)};
        var locate = JsonNode.Parse(await client.GetStringAsync("https://locate.measurementlab.net/v2/nearest/ndt/ndt7", cancellation))!;
        var node = locate["results"]?.AsArray().FirstOrDefault() ?? throw new IOException("Locate API не вернул узел NDT7.");
        var urls = node["urls"]!;
        Result("speed_node", "info", $"{Text(node, "machine")}, город {Text(node["location"], "city")}");
        foreach (var direction in new[] {"download", "upload"})
        {
            var url = Text(urls, $"wss:///ndt/v7/{direction}");
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "wss") throw new IOException("Locate API вернул неверный WSS URL.");
            using var socket = new ClientWebSocket(); socket.Options.AddSubProtocol("net.measurementlab.ndt.v7");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await socket.ConnectAsync(uri, client, timeout.Token);
            if (direction == "upload")
            {
                await Upload(socket, uri.Host);
                continue;
            }
            var clock = Stopwatch.StartNew();
            long bytes = 0;
            var buffer = new byte[64 * 1024];
            using var measurement = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            measurement.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                while (true)
                {
                    var response = await socket.ReceiveAsync(buffer.AsMemory(), measurement.Token);
                    if (response.MessageType == WebSocketMessageType.Close) break;
                    if (response.MessageType == WebSocketMessageType.Binary) bytes += response.Count;
                }
            }
            catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) {}
            clock.Stop();
            Result("speed_download", bytes > 0 ? "ok" : "unconfirmed", bytes > 0
                ? $"{uri.Host}: {bytes * 8 / clock.Elapsed.TotalSeconds / 1_000_000:F2} Мбит/с, один TCP-поток, {clock.Elapsed.TotalSeconds:F1} с."
                : "Данные загрузки не получены.");
        }
    }

    private sealed record UploadSample(long Bytes, long Microseconds);

    private async Task Upload(ClientWebSocket socket, string host)
    {
        var clock = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(13));
        var buffer = RandomNumberGenerator.GetBytes(8192);
        UploadSample? application = null, tcp = null;
        var receive = ReadUploadMeasurements(socket, deadline.Token, message =>
        {
            application = Sample(message, "AppInfo", "NumBytes") ?? application;
            tcp = Sample(message, "TCPInfo", "BytesReceived") ?? tcp;
        });
        string? issue = null;
        try
        {
            while (!receive.IsCompleted && clock.Elapsed < TimeSpan.FromSeconds(10))
            {
                await socket.SendAsync(buffer.AsMemory(), WebSocketMessageType.Binary, true, deadline.Token);
            }
            if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
                await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "", deadline.Token);
        }
        catch (Exception error) when (error is WebSocketException or OperationCanceledException)
        {
            issue = error.Message;
        }
        try { await receive; }
        catch (Exception error) when (error is WebSocketException or OperationCanceledException)
        {
            issue ??= error.Message;
        }
        cancellation.ThrowIfCancellationRequested();
        if (deadline.IsCancellationRequested) issue = "Достигнут предел ожидания 13 с.";
        var sample = application ?? tcp;
        var detail = sample == null
            ? "Нет серверного замера отдачи." + (issue == null ? "" : $" {issue}")
            : $"{host}: {sample.Bytes * 8.0 / sample.Microseconds:F2} Мбит/с, один TCP-поток, {sample.Microseconds / 1_000_000.0:F1} с.";
        Result("speed_upload", sample == null ? "unconfirmed" : "ok", detail);
    }

    private static UploadSample? Sample(JsonNode? message, string source, string counter)
    {
        if (message is JsonObject obj && obj[source] is JsonObject info &&
            info["ElapsedTime"] is JsonValue time && time.TryGetValue<long>(out var microseconds) && microseconds > 0 &&
            info[counter] is JsonValue count && count.TryGetValue<long>(out var bytes) && bytes >= 0)
            return new UploadSample(bytes, microseconds);
        return null;
    }

    private static async Task ReadUploadMeasurements(ClientWebSocket socket, CancellationToken token, Action<JsonNode?> report)
    {
        byte[] buffer = new byte[16 * 1024];
        using var message = new MemoryStream();
        while (true)
        {
            var frame = await socket.ReceiveAsync(buffer.AsMemory(), token);
            if (frame.MessageType == WebSocketMessageType.Close) return;
            if (frame.MessageType != WebSocketMessageType.Text) continue;
            if (message.Length + frame.Count > 1 << 24) throw new IOException("Слишком длинное сообщение NDT7.");
            message.Write(buffer, 0, frame.Count);
            if (!frame.EndOfMessage) continue;
            message.Position = 0;
            report(JsonNode.Parse(message));
            message.SetLength(0);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (writer != null && pipe.IsConnected)
        {
            try {await Local(new JsonObject {["command"] = "end"});} catch {}
        }
        writer?.Dispose(); reader?.Dispose(); await pipe.DisposeAsync();
    }
}
