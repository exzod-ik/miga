using Miga.Diagnostics;
using System.Text.Json.Nodes;

static void Check(bool condition) {if (!condition) throw new Exception("Report assertion failed");}
var response = JsonNode.Parse("""
{"ok":true,"network":{"interface":"ens192","elapsed_ms":30000,"ring":{"rx":4096,"rx_max":4096},"socket_rcvbuf":8388608,
"delta":{"driver/pkts rx OOB/0":19596,"socket/drops":0,"interface/rx_packets":16275,"interface/tx_packets":100,
"softnet/cpu0/dropped":0,"softnet/cpu0/time_squeeze":23},"unavailable":[],"invalid":[]}}
""")!.AsObject();
var report = ServerNetworkReport.Format(response);
Check(report.Status == "warning" && report.Detail.Contains("не хватило приёмных буферов карты"));
Check(report.Detail.Contains("не число потерянных пакетов") && report.Detail.Contains("включая фоновый трафик"));
response["network"]!["delta"]!["driver/pkts rx OOB/0"] = 0;
response["network"]!["delta"]!["softnet/cpu0/time_squeeze"] = 0;
Check(ServerNetworkReport.Format(response).Status == "info");
response["network"]!["delta"]!["socket/drops"] = null;
Check(ServerNetworkReport.Format(response).Detail.Contains("Отброшено сокетом MIGA: нет данных"));
Check(ServerNetworkReport.Format(new JsonObject { ["ok"] = false }).Status == "unavailable");
Check(ServerNetworkReport.Format(JsonNode.Parse("""{"ok":true,"network":{"delta":{}}}""")!.AsObject()).Status == "unavailable");
var begin = JsonNode.Parse("""{"ok":true,"network":{"interface":"test","elapsed_ms":1000,"delta":{"socket/drops":100}}}""")!.AsObject();
var end = JsonNode.Parse("""{"ok":true,"network":{"interface":"test","elapsed_ms":31000,"delta":{"socket/drops":107}}}""")!.AsObject();
Check(ServerNetworkReport.FormatInterval(begin, end).Contains("Отброшено сокетом MIGA: 7."));
end["network"]!["delta"]!["socket/drops"] = 3;
Check(ServerNetworkReport.FormatInterval(begin, end).Contains("Отброшено сокетом MIGA: нет данных"));
Console.WriteLine("ServerNetworkReport tests passed");
