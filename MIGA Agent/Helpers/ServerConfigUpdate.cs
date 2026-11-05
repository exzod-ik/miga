using System.Text.Json;
using System.Text.Json.Nodes;
using MIGA_Agent.Models;

namespace MIGA_Agent.Helpers;

public static class ServerConfigUpdate
{
    public static string? Prepare(string currentJson, ServerConfig desired)
    {
        var current = JsonNode.Parse(currentJson) as JsonObject
            ?? throw new JsonException("Конфигурация сервера должна быть JSON-объектом.");
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
