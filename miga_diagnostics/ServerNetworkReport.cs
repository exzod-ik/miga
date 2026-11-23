using System.Text.Json.Nodes;

namespace Miga.Diagnostics;

public static class ServerNetworkReport
{
    public static string FormatInterval(JsonObject before, JsonObject after)
    {
        if (before["network"] is not JsonObject first || after["network"] is not JsonObject last ||
            first["delta"] is not JsonObject a || last["delta"] is not JsonObject b ||
            first["interface"]?.ToJsonString() != last["interface"]?.ToJsonString())
            return "Сетевые показатели за ступень недоступны.";
        var copy = (JsonObject)after.DeepClone();
        var delta = new JsonObject();
        foreach (var item in b)
            delta[item.Key] = item.Value is JsonValue end && end.TryGetValue<ulong>(out var y) &&
                a[item.Key] is JsonValue begin && begin.TryGetValue<ulong>(out var x) && y >= x ? JsonValue.Create(y - x) : null;
        copy["network"]!["delta"] = delta;
        copy["network"]!["elapsed_ms"] = Math.Max(0, (last["elapsed_ms"]?.GetValue<long>() ?? 0) - (first["elapsed_ms"]?.GetValue<long>() ?? 0));
        return Format(copy).Detail.Replace("За сеанс:", "За ступень:");
    }

    public static (string Status, string Detail) Format(JsonObject response)
    {
        if (response["ok"]?.GetValue<bool>() != true || response["network"] is not JsonObject network)
            return ("unavailable", "Сервер не предоставил сетевые показатели. Возможно, требуется обновление сервера.");
        var lines = new List<string>();
        var name = network["interface"]?.GetValue<string>();
        var elapsed = network["elapsed_ms"]?.GetValue<long>() ?? 0;
        lines.Add($"Интерфейс: {(string.IsNullOrEmpty(name) ? "не определён" : name)}; интервал наблюдения: {elapsed / 1000.0:F1} с.");
        if (network["ring"] is JsonObject ring)
            lines.Add($"RX-кольцо: {ring["rx"]}, максимум: {ring["rx_max"]}.");
        else lines.Add("Размер RX-кольца: нет данных.");
        if (network["socket_rcvbuf"] is JsonValue buffer)
            lines.Add($"Буфер приёма сокета MIGA: {buffer.GetValue<long>() / 1048576.0:F1} МиБ.");
        var delta = network["delta"] as JsonObject ?? new JsonObject();
        ulong? Value(string key) => delta[key] is JsonValue value && value.TryGetValue<ulong>(out var number) ? number : null;
        string Count(string key) => Value(key)?.ToString("N0") ?? "нет данных";
        lines.Add($"За сеанс: принято интерфейсом {Count("interface/rx_packets")} пакетов, отправлено {Count("interface/tx_packets")}.");
        lines.Add($"Отброшено сокетом MIGA: {Count("socket/drops")}.");
        var warning = Value("socket/drops") is > 0;
        var anyCounter = delta.Any(item => item.Value is JsonValue);
        foreach (var (key, label) in new[] {
            ("interface/rx_dropped", "RX drops интерфейса"), ("interface/rx_errors", "Ошибки RX"),
            ("interface/rx_missed_errors", "Пропуски RX"), ("interface/rx_fifo_errors", "Ошибки RX FIFO"),
            ("interface/tx_dropped", "TX drops интерфейса"), ("interface/tx_errors", "Ошибки TX") })
        {
            lines.Add($"{label}: {Count(key)}.");
            warning |= Value(key) is > 0;
        }
        var driver = delta.Where(item => item.Key.StartsWith("driver/", StringComparison.Ordinal)).ToArray();
        var driverAvailable = driver.Any(item => item.Value is JsonValue);
        var changed = false;
        foreach (var item in driver)
        {
            var count = Value(item.Key);
            if (count is not > 0) continue;
            changed = true; warning = true;
            var label = item.Key[7..];
            var split = label.LastIndexOf('/');
            if (split >= 0) label = label[..split] + $" [счётчик {label[(split + 1)..]}]";
            var meaning = item.Key.Contains("oob", StringComparison.OrdinalIgnoreCase) ? " — не хватило приёмных буферов карты" : "";
            lines.Add($"Драйвер: {label} +{count:N0}{meaning}.");
        }
        if (!changed) lines.Add(driverAvailable ? "Доступные счётчики потерь и ошибок RX драйвера: прироста нет." : "Счётчики потерь RX драйвера: нет данных.");
        foreach (var suffix in new[] { "/dropped", "/time_squeeze" })
        {
            var entries = delta.Where(item => item.Key.StartsWith("softnet/", StringComparison.Ordinal) && item.Key.EndsWith(suffix, StringComparison.Ordinal)).ToArray();
            var valid = entries.Length > 0 && entries.All(item => Value(item.Key).HasValue);
            var total = valid ? entries.Aggregate(0UL, (sum, item) => sum + Value(item.Key)!.Value) : (ulong?)null;
            var label = suffix == "/dropped" ? "Отброшено сетевым стеком (все CPU)" : "Исчерпан бюджет обработки сети (не число потерянных пакетов)";
            lines.Add($"{label}: {total?.ToString("N0") ?? "нет данных"}.");
            warning |= total is > 0;
        }
        if (network["unavailable"] is JsonArray missing && missing.Count > 0)
            lines.Add("Недоступные источники: " + string.Join(", ", missing.Select(item => item?.GetValue<string>())) + ".");
        if (network["invalid"] is JsonArray invalid && invalid.Count > 0)
            lines.Add("Часть изменений не вычислена: счётчик сброшен, источник изменился или один из снимков отсутствует.");
        lines.Add("Прирост относится ко всему интерфейсу/сетевому стеку и сокету MIGA, включая фоновый трафик. Счётчики могут перекрываться; их нельзя складывать или считать процентом потерь теста.");
        return (warning ? "warning" : anyCounter ? "info" : "unavailable", string.Join("\n", lines));
    }
}
