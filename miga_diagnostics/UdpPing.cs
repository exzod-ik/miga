using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Miga.Diagnostics;

public sealed partial class DiagnosticRunner
{
    private const string DirectStunHost = "stun.cloudflare.com";
    private const int DirectStunPort = 3478;

    private static byte[] CreateStunRequest(int size)
    {
        var request = new byte[size];
        BinaryPrimitives.WriteUInt16BigEndian(request, 0x0001);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)(size - 20));
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), 0x2112A442);
        RandomNumberGenerator.Fill(request.AsSpan(8, 12));
        return request;
    }

    private static bool MatchesStunBinding(ReadOnlySpan<byte> reply, byte[] request) =>
        reply.Length >= 20 && BinaryPrimitives.ReadUInt16BigEndian(reply) == 0x0101 &&
        BinaryPrimitives.ReadUInt32BigEndian(reply[4..]) == 0x2112A442 &&
        reply.Slice(8, 12).SequenceEqual(request.AsSpan(8, 12)) &&
        BinaryPrimitives.ReadUInt16BigEndian(reply[2..]) + 20 == reply.Length;

    internal static bool IsDirectStunReply(ReadOnlySpan<byte> reply, byte[] request)
    {
        if (!MatchesStunBinding(reply, request) || reply.Length % 4 != 0) return false;
        bool mappedAddress = false;
        for (int offset = 20; offset < reply.Length;)
        {
            var attribute = reply[offset..];
            int type = BinaryPrimitives.ReadUInt16BigEndian(attribute);
            int size = BinaryPrimitives.ReadUInt16BigEndian(attribute[2..]);
            int paddedSize = (size + 3) & ~3;
            if (paddedSize > attribute.Length - 4) return false;
            if (type == 0x0020 && size == 8 && attribute[5] == 1) mappedAddress = true;
            offset += 4 + paddedSize;
        }
        return mappedAddress;
    }

    private async Task DirectPing(int seconds)
    {
        if (seconds is < 1 or > 3600) throw new ArgumentOutOfRangeException(nameof(seconds), "Длительность прямого UDP-пинга — от 1 до 3600 секунд.");
        using var setup = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        setup.CancelAfter(TimeSpan.FromSeconds(5));
        var addresses = await Dns.GetHostAddressesAsync(DirectStunHost, AddressFamily.InterNetwork, setup.Token);
        if (addresses.Length == 0) throw new IOException($"У {DirectStunHost} нет IPv4-адреса.");
        var endpoint = new IPEndPoint(addresses[0], DirectStunPort);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) {ExclusiveAddressUse = true};
        await socket.ConnectAsync(endpoint, setup.Token);
        var local = (IPEndPoint)socket.LocalEndPoint!;
        var response = await Local(new JsonObject
        {
            ["command"] = "direct_probe_register",
            ["local_ip"] = BinaryPrimitives.ReadUInt32BigEndian(local.Address.GetAddressBytes()),
            ["local_port"] = local.Port,
            ["remote_ip"] = BinaryPrimitives.ReadUInt32BigEndian(endpoint.Address.GetAddressBytes())
        });
        if (response["ok"]?.GetValue<bool>() != true)
        {
            Result("direct_ping", "unavailable", "Локальная служба MIGA не подтвердила прямой маршрут для STUN-сокета.");
            return;
        }

        using var probeLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        var watch = WatchDirectProbePipe(probeLifetime);
        try {await MeasureDirectPing(socket, endpoint, seconds, probeLifetime.Token);}
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {throw new IOException("Локальная служба MIGA закрыла прямой маршрут во время пробы.");}
        finally
        {
            probeLifetime.Cancel();
            if (await watch && !cancellation.IsCancellationRequested)
                await Local(new JsonObject {["command"] = "direct_probe_end"});
        }
    }

    private async Task<bool> WatchDirectProbePipe(CancellationTokenSource lifetime)
    {
        try {await reader!.ReadLineAsync(lifetime.Token);}
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) {return true;}
        catch (IOException) {}
        lifetime.Cancel();
        return false;
    }

    private async Task MeasureDirectPing(Socket socket, IPEndPoint endpoint, int seconds, CancellationToken token)
    {
        var samples = new List<(double SentAt, double? Rtt, string? Error)>(seconds);
        var buffer = new byte[2048];
        var clock = Stopwatch.StartNew();
        int sent = 0, replies = 0, timeouts = 0;
        for (int sample = 0; sample < seconds; sample++)
        {
            var delay = TimeSpan.FromSeconds(sample) - clock.Elapsed;
            if (delay > TimeSpan.Zero) await Task.Delay(delay, token);
            token.ThrowIfCancellationRequested();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(950);
            var request = CreateStunRequest(20);
            var started = clock.Elapsed;
            double? rtt = null;
            string? error = null;
            bool submitted = false;
            try
            {
                await socket.SendAsync(request, SocketFlags.None, timeout.Token);
                submitted = true;
                sent++;
                while (true)
                {
                    int size = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
                    if (!IsDirectStunReply(buffer.AsSpan(0, size), request)) continue;
                    rtt = (clock.Elapsed - started).TotalMilliseconds;
                    replies++;
                    break;
                }
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                if (submitted) timeouts++;
                else error = "тайм-аут отправки";
            }
            catch (SocketException exception)
            {
                token.ThrowIfCancellationRequested();
                error = $"ошибка {(submitted ? "приёма" : "отправки")} ({exception.SocketErrorCode})";
            }
            samples.Add((started.TotalSeconds, rtt, error));
            Program.Output(new {kind = "ping_progress", detail = $"Прямой UDP-пинг · {sample + 1}/{seconds} · отправлено {sent}, ответов {replies}"});
        }
        token.ThrowIfCancellationRequested();
        var rtts = samples.Where(x => x.Rtt.HasValue).Select(x => x.Rtt!.Value).Order().ToArray();
        int errors = samples.Count(x => x.Error != null);
        var detail = $"{DirectStunHost} ({endpoint}) напрямую по IPv4/UDP. Отправлено {sent}, ответов {replies}, без ответа за 950 мс {timeouts}, ошибок сокета {errors}.";
        if (rtts.Length > 0)
            detail += $"\nRTT, мс: min {rtts[0]:F1}, средний {rtts.Average():F1}, p95 {rtts[(int)Math.Ceiling(rtts.Length * .95) - 1]:F1}, max {rtts[^1]:F1}.";
        detail += "\n" + string.Join("\n", samples.Select(x => $"{x.SentAt:F2} с: {x.Error ?? (x.Rtt is double ms ? $"{ms:F1} мс" : "нет ответа")}"));
        var status = replies == 0 ? "failed" : replies < seconds ? "warning" : "ok";
        report.Add($"direct_ping: {status}\n{detail}");
        Program.Output(new {kind = "result", step = "direct_ping", status, detail, series = samples.Select(x => new {second = x.SentAt, rtt = x.Rtt}).ToArray()});
    }

    private async Task Ping(TimeSpan duration, CancellationToken token)
    {
        using var socket = await Bind(17);
        var endpoint = new IPEndPoint(IPAddress.Parse(Text(prepared, "echo_ip")), prepared["echo_port"]!.GetValue<int>());
        var secret = Convert.FromHexString(Text(prepared, "token"));
        var clock = Stopwatch.StartNew();
        var gate = new object();
        var probes = new Dictionary<int, (double Sent, double? Rtt, bool Error)>();
        var duplicates = 0; string receiveError = "";
        using var receiveStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task Receive()
        {
            var buffer = new byte[128];
            try
            {
                while (!receiveStop.IsCancellationRequested)
                {
                    var reply = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), receiveStop.Token);
                    if (!reply.RemoteEndPoint.Equals(endpoint) || reply.ReceivedBytes < 20 || !buffer.AsSpan(0, 16).SequenceEqual(secret)) continue;
                    int id = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(16));
                    lock (gate)
                    {
                        if (!probes.TryGetValue(id, out var probe)) continue;
                        if (probe.Rtt != null) { duplicates++; continue; }
                        probes[id] = (probe.Sent, (clock.Elapsed.TotalSeconds - probe.Sent) * 1000, probe.Error);
                    }
                }
            }
            catch (OperationCanceledException) when (receiveStop.IsCancellationRequested) { }
            catch (SocketException error) { receiveError = error.SocketErrorCode.ToString(); }
        }
        var receiver = Receive();
        try
        {
            for (int sample = 0; sample < Math.Min(6000, duration.TotalSeconds); sample++)
            {
                var delay = sample - clock.Elapsed.TotalSeconds;
                if (delay > 0) await Task.Delay(TimeSpan.FromSeconds(delay), token);
                token.ThrowIfCancellationRequested();
                int id = Interlocked.Increment(ref sequence);
                var data = new byte[20]; secret.CopyTo(data, 0); BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(16), id);
                lock (gate) probes[id] = (clock.Elapsed.TotalSeconds, null, false);
                try { await socket.SendToAsync(data, SocketFlags.None, endpoint, token); }
                catch (SocketException) { lock (gate) { var p = probes[id]; probes[id] = (p.Sent, null, true); } }
                lock (gate)
                {
                    var last = probes.Values.LastOrDefault(x => x.Rtt != null).Rtt;
                    Program.Output(new { kind = "ping_progress", detail = $"UDP-пинг: отправлено {probes.Count}, ответов {probes.Values.Count(x => x.Rtt != null)}, последний RTT {(last is null ? "—" : $"{last:F1} мс")}" });
                }
            }
            await Task.Delay(2500, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally { receiveStop.Cancel(); await receiver; }
        var values = probes.Values.ToArray();
        var rtts = values.Where(x => x.Rtt != null).Select(x => x.Rtt!.Value).ToArray();
        var sorted = rtts.Order().ToArray();
        int failed = values.Count(x => x.Error), pending = values.Count(x => !x.Error && x.Rtt == null && clock.Elapsed.TotalSeconds - x.Sent < 2.5);
        int lost = values.Count(x => !x.Error && x.Rtt == null) - pending;
        var detail = $"Через MIGA до сервера: отправлено {values.Length - failed}, ответов {rtts.Length}, потеряно {lost} ({(values.Length == failed ? 0 : 100.0 * lost / (values.Length - failed)):F2}%), незавершённых {pending}, ошибок отправки {failed}, дубликатов {duplicates}.";
        if (rtts.Length > 0)
        {
            var jitter = rtts.Length > 1 ? rtts.Zip(rtts.Skip(1), (a, b) => Math.Abs(a - b)).Average() : 0;
            detail += $"\nRTT, мс: последний {rtts[^1]:F1}, min {sorted[0]:F1}, средний {rtts.Average():F1}, p95 {sorted[(int)Math.Ceiling(sorted.Length * .95) - 1]:F1}, max {sorted[^1]:F1}; средний разброс соседних ответов {jitter:F1}.";
        }
        if (receiveError.Length > 0) detail += "\nОшибка приёма: " + receiveError;
        detail += "\n" + string.Join("\n", values.Select(x => $"{x.Sent:F1} с: {(x.Error ? "ошибка отправки" : x.Rtt is null ? "нет ответа" : $"{x.Rtt:F1} мс")}"));
        var status = lost > 0 || failed > 0 || receiveError.Length > 0 ? "warning" : "ok";
        report.Add("ping: " + status + "\n" + detail);
        Program.Output(new { kind = "result", step = "ping", status, detail, series = values.Select(x => new { second = x.Sent, rtt = x.Rtt }).ToArray() });
    }
}
