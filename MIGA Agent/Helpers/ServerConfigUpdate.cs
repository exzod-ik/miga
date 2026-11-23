using System.Text.Json;
using System.Text.Json.Nodes;
using MIGA_Agent.Models;

namespace MIGA_Agent.Helpers;

public static class ServerConfigUpdate
{
    public static void Validate(ServerConfig desired)
    {
        if (desired.LogLevel is not ("none" or "error" or "warning" or "info" or "debug"))
            throw new System.IO.InvalidDataException("Выберите допустимый уровень журналирования.");
        if (desired.DnsServer == "") return;
        var octets = desired.DnsServer?.Split('.');
        if (octets == null || octets.Length != 4 || octets.Any(octet =>
            octet.Length is < 1 or > 3 || octet.Length > 1 && octet[0] == '0' ||
            octet.Any(character => character is < '0' or > '9') || !byte.TryParse(octet, out _)))
            throw new System.IO.InvalidDataException("Укажите DNS-сервер в виде IPv4-адреса или оставьте поле пустым.");
    }

    public static string? Prepare(string currentJson, ServerConfig desired)
    {
        Validate(desired);
        var current = JsonNode.Parse(currentJson) as JsonObject
            ?? throw new JsonException("Конфигурация сервера должна быть JSON-объектом.");
        if (current["protocol"]?.GetValue<int>() != 2)
            throw new JsonException("Поддерживается только MIGA.");
        var next = JsonSerializer.SerializeToNode(desired)!.AsObject();
        bool changed = false;
        foreach (var property in next)
        {
            if (JsonNode.DeepEquals(current[property.Key], property.Value)) continue;
            current[property.Key] = property.Value?.DeepClone();
            changed = true;
        }
        return changed ? current.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) : null;
    }
}
