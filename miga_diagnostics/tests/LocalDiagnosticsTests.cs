using System.IO.Pipes;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using Miga.Diagnostics;

internal static class LocalDiagnosticsTests
{
    public static async Task Main()
    {
        CheckStunReplies();
        CheckObservedRoutes();
        foreach (bool localOnly in new[] {true, false})
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            string name = "miga-test-" + Guid.NewGuid().ToString("N");
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var backend = Task.Run(async () =>
            {
                await server.WaitForConnectionAsync(timeout.Token);
                using var reader = new StreamReader(server, Encoding.UTF8, false, 4096, true);
                using var writer = new StreamWriter(server, new UTF8Encoding(false), 4096, true) {AutoFlush = true};
                int windows = 0;
                bool observing = false;
                while (await reader.ReadLineAsync(timeout.Token) is { } line)
                {
                    var request = JsonNode.Parse(line)!;
                    var command = request["command"]!.GetValue<string>();
                    if (command == "begin" && request["profile_id"]?.GetValue<string>() != "test-profile") throw new Exception("profile selection lost");
                    var response = new JsonObject {["ok"] = true, ["local_only"] = localOnly};
                    if (command == "observe_begin")
                    {
                        if (observing) throw new Exception("overlapping observation");
                        observing = true;
                        ++windows;
                    }
                    if (command == "observe_end")
                    {
                        if (!observing) throw new Exception("observation window missing");
                        observing = false;
                        response["captured"] = 1;
                        response["flows"] = !localOnly && windows == 2 ? new JsonArray(ObservedFlow("direct", 0)) : new JsonArray();
                    }
                    if (command == "stats")
                    {
                        response["captured"] = 42;
                        response["flows"] = new JsonArray(ObservedFlow("direct", 0));
                    }
                    await writer.WriteLineAsync(response.ToJsonString());
                    if (command == "end") return;
                }
            });
            var config = new JsonObject {["profile_id"] = "test-profile", ["mode"] = "rules", ["target_pid"] = 1,
                ["steps"] = localOnly ? new JsonArray("capture", "route", "first_leg", "tcp", "udp", "mss", "speed", "load", "ping") : new JsonArray("capture", "route")};
            var output = new StringWriter(); var previous = Console.Out;
            try
            {
                Console.SetOut(output);
                await using (var runner = new DiagnosticRunner(config, timeout.Token, name)) await runner.Run();
                await backend;
            }
            finally {Console.SetOut(previous);}
            var messages = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => JsonNode.Parse(x)!).ToArray();
            if (messages.Any(x => x["kind"]?.GetValue<string>() == "control")) throw new Exception("local run requested server control");
            if (!HasResult("capture", "ok")) throw new Exception("capture did not use current packet count");
            if (!HasResult("route", localOnly ? "unconfirmed" : "ok")) throw new Exception("route did not use current flow observations");
            bool HasResult(string step, string status) => messages.Any(x => x["step"]?.GetValue<string>() == step &&
                x["status"]?.GetValue<string>() == status);
            if (localOnly && messages.Count(x => x["status"]?.GetValue<string>() == "skipped") != 7) throw new Exception("unauthenticated remote checks were not skipped");
        }
        Console.WriteLine("Local diagnostics: capture/route without authorization; seven remote checks skipped; local-only selection never opens server control: passed");
    }

    private static JsonObject ObservedFlow(string route, ulong serverId) => new()
    {
        ["pid"] = 1, ["application"] = "miga-test", ["remote_ip"] = 0xc0000201u, ["remote_port"] = 47901,
        ["route"] = route, ["server_id"] = serverId, ["reason"] = "test"
    };

    private static void CheckObservedRoutes()
    {
        if (!DiagnosticRunner.MatchesObservedRoute(ObservedFlow("tunnel", 5), false, 5))
            throw new Exception("selected tunnel was not confirmed");
        if (DiagnosticRunner.MatchesObservedRoute(ObservedFlow("tunnel", 4), false, 5) ||
            DiagnosticRunner.MatchesObservedRoute(ObservedFlow("direct", 0), false, 5) ||
            DiagnosticRunner.MatchesObservedRoute(ObservedFlow("tunnel", 5), false, null))
            throw new Exception("forced tunnel confirmed an unrelated route");
    }

    private static void CheckStunReplies()
    {
        var request = Convert.FromHexString("000100002112A442000102030405060708090A0B");
        var reply = Convert.FromHexString("0101000C2112A442000102030405060708090A0B0020000800012113E112A640");
        if (!DiagnosticRunner.IsDirectStunReply(reply, request)) throw new Exception("valid STUN reply rejected");
        if (DiagnosticRunner.IsDirectStunReply(reply.AsSpan(0, 19), request)) throw new Exception("short STUN header accepted");
        if (DiagnosticRunner.IsDirectStunReply(reply.AsSpan(0, 31), request)) throw new Exception("truncated STUN datagram accepted");

        reply[8] ^= 1;
        if (DiagnosticRunner.IsDirectStunReply(reply, request)) throw new Exception("unrelated STUN transaction accepted");
        reply[8] ^= 1;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(22), 9);
        if (DiagnosticRunner.IsDirectStunReply(reply, request)) throw new Exception("truncated STUN attribute accepted");
        Console.WriteLine("Direct STUN response validation: passed");
    }
}
