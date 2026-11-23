using Miga.Diagnostics;
using System.Text.Json.Nodes;

var settings = LoadSettings.Parse(new JsonObject());
if (settings.Seconds != 60 || settings.Rates.Length != 6) throw new Exception("defaults");
foreach (var invalid in new[] {new JsonObject {["load_seconds"] = 301}, new JsonObject {["load_bytes"] = 2}, new JsonObject {["load_rates"] = "100,50"}, new JsonObject {["load_rates"] = "100,100"}, new JsonObject {["load_repeats"] = 6}})
{
    bool rejected = false; try { LoadSettings.Parse(invalid); } catch { rejected = true; }
    if (!rejected) throw new Exception("limits");
}
var probe = LoadProbe.Create(123, 7, 0, 64);
System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(probe.AsSpan(16), 11);
if (LoadProbe.Read(probe, 123, 7, 0) != 11 || LoadProbe.Read(probe, 123, 8, 0) != -1 || LoadProbe.Read(probe.AsSpan(0, 31), 123, 7, 0) != -1) throw new Exception("identity");
var sent = new ProbeCounter(10, 2); var received = new ProbeCounter(10, 2);
for (int i = 0; i < 20; i++) sent.Record(i);
for (int i = 19; i >= 5; i--) received.Record(i);
received.Record(19); received.Record(100); received.Record(0, false);
var s = received.Snapshot();
if (s["unique"]!.GetValue<long>() != 15 || s["duplicates"]!.GetValue<long>() != 1 || s["reordered"]!.GetValue<long>() != 14 || s["seconds"]![0]!.GetValue<long>() != 5) throw new Exception("counting");
var text = DiagnosticRunner.FormatLoad(new (string, JsonNode)[] {("sender", sent.Snapshot()), ("receiver", s)}, 10, new(2, 64, 1, [10]), 2);
if (!text.Contains("15/20") || !text.Contains("25")) throw new Exception("loss report");
Console.WriteLine("Load measurement: bounds, run/step identity, unique/reordered/duplicate counts, second bins and loss report passed");

using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
var pipeName = "miga-load-test-" + Guid.NewGuid().ToString("N");
using var backend = new System.IO.Pipes.NamedPipeServerStream(pipeName, System.IO.Pipes.PipeDirection.InOut, 1, System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.Asynchronous);
var service = Task.Run(async () => {
    await backend.WaitForConnectionAsync(deadline.Token);
    using var input = new StreamReader(backend, System.Text.Encoding.UTF8, false, 4096, true);
    using var output = new StreamWriter(backend, new System.Text.UTF8Encoding(false), 4096, true) {AutoFlush = true};
    while (await input.ReadLineAsync(deadline.Token) is { } line) {
        var request = JsonNode.Parse(line)!;
        await output.WriteLineAsync(new JsonObject {["ok"] = true, ["marker"] = request["marker"]?.DeepClone()}.ToJsonString());
        if (request["command"]?.GetValue<string>() == "end") break;
    }
});
var runner = new DiagnosticRunner(new JsonObject(), deadline.Token, pipeName);
var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
var type = typeof(DiagnosticRunner);
var pipe = (System.IO.Pipes.NamedPipeClientStream)type.GetField("pipe", flags)!.GetValue(runner)!;
await pipe.ConnectAsync(deadline.Token);
type.GetField("reader", flags)!.SetValue(runner, new StreamReader(pipe, System.Text.Encoding.UTF8, false, 4096, true));
type.GetField("writer", flags)!.SetValue(runner, new StreamWriter(pipe, new System.Text.UTF8Encoding(false), 4096, true) {AutoFlush = true});
var local = type.GetMethod("Local", flags)!;
await Task.WhenAll(Enumerable.Range(0, 20).Select(async marker => {
    var result = await (Task<JsonObject>)local.Invoke(runner, [new JsonObject {["command"] = "test", ["marker"] = marker}])!;
    if (result["marker"]!.GetValue<int>() != marker) throw new Exception("concurrent pipe response crossed");
}));
Console.WriteLine("Concurrent local commands preserve response ownership: passed");
if (!args.Contains("--udp-loopback")) {
    await runner.DisposeAsync(); await service;
    return;
}
using var echo = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
echo.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
var endpoint = (System.Net.IPEndPoint)echo.LocalEndPoint!;
type.GetField("prepared", flags)!.SetValue(runner, new JsonObject {["echo_ip"] = "127.0.0.1", ["echo_port"] = endpoint.Port, ["token"] = new string('a', 32)});
var responder = Task.Run(async () => {
    var buffer = new byte[128];
    for (int i = 0; i < 2; i++) {
        var packet = await echo.ReceiveFromAsync(buffer, System.Net.Sockets.SocketFlags.None, new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0), deadline.Token);
        if (i == 0) {
            await echo.SendToAsync(buffer.AsMemory(0, packet.ReceivedBytes), System.Net.Sockets.SocketFlags.None, packet.RemoteEndPoint, deadline.Token);
            await echo.SendToAsync(buffer.AsMemory(0, packet.ReceivedBytes), System.Net.Sockets.SocketFlags.None, packet.RemoteEndPoint, deadline.Token);
        }
    }
});
var savedOutput = Console.Out; var captured = new StringWriter();
try {
    Console.SetOut(captured);
    await (Task)type.GetMethod("Ping", flags)!.Invoke(runner, [TimeSpan.FromSeconds(2), deadline.Token])!;
    await responder;
    await runner.DisposeAsync(); await service;
} finally { Console.SetOut(savedOutput); }
var resultLine = captured.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => JsonNode.Parse(x)!).Single(x => x["kind"]?.GetValue<string>() == "result");
var detail = resultLine["detail"]!.GetValue<string>();
if (!detail.Contains("ответов 1") || !detail.Contains("потеряно 1") || !detail.Contains("дубликатов 1") || resultLine["series"]!.AsArray().Count != 2) throw new Exception("UDP ping loss/duplicate accounting");
Console.WriteLine("Concurrent local commands and real loopback UDP ping with duplicate and deliberately missing reply passed");
