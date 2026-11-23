using System.IO;
using System.Text.Json;
using MIGA_Agent.Models;

namespace MIGA_Agent.Services;

public static class ClientConfigCodec
{
    public static ClientConfig Decode(string json, out bool migrated)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        CheckObject(root);
        int version = root.TryGetProperty("protocol", out var protocol) ? ReadVersion(protocol) : 1;
        migrated = version == 1;
        var config = new ClientConfig
        {
            LogLevel = ReadString(root, "log_level", "none"),
            DnsResolverEnabled = ReadBoolean(root, "dns_resolver_enabled", true),
            RoutingMode = ReadString(root, "routing_mode", "split"),
            FullRoutingProfileId = ReadString(root, "full_routing_profile_id", ""),
            TunnelMaxMss = root.TryGetProperty("tunnel_max_mss", out var mss) && mss.ValueKind == JsonValueKind.Number && mss.TryGetInt32(out var value)
                ? value : root.TryGetProperty("tunnel_max_mss", out _) ? throw Invalid() : 1400
        };
        if (root.TryGetProperty("servers", out var servers))
        {
            if (servers.ValueKind != JsonValueKind.Array || servers.GetArrayLength() > 1000) throw Invalid();
            foreach (var server in servers.EnumerateArray()) config.Servers.Add(ReadServer(server, version));
        }
        else if (migrated) config.Servers.Add(ReadServer(root, version));
        else throw Invalid();
        Validate(config);
        return config;
    }

    private static ServerEntry ReadServer(JsonElement element, int version)
    {
        CheckObject(element);
        int transport = element.TryGetProperty("protocol", out var protocol) ? ReadVersion(protocol) : 1;
        if (transport != version) throw Invalid();
        bool legacy = version == 1;
        bool pending = legacy;
        if (!legacy)
        {
            if (element.TryGetProperty("encryption", out _) || element.TryGetProperty("server_ports", out _)) throw Invalid();
            pending = ReadBoolean(element, "requires_invitation", false);
        }
        else
        {
            if (element.TryGetProperty("profile_id", out _) || element.TryGetProperty("requires_invitation", out _)) throw Invalid();
            if (!element.TryGetProperty("server_ports", out var ports) || ports.ValueKind != JsonValueKind.Object ||
                !element.TryGetProperty("encryption", out var encryption) || encryption.ValueKind != JsonValueKind.Object) throw Invalid();
        }
        var result = new ServerEntry
        {
            Enabled = ReadBoolean(element, "enabled", true),
            ServerIp = ReadString(element, "server_ip", ""),
            ConnectionName = ReadString(element, "connection_name", ""),
            ProfileId = legacy ? null : ReadString(element, "profile_id", ""),
            RequiresInvitation = pending,
            RedirectProcesses = ReadRules(element, "redirect_processes"),
            RedirectIps = ReadRules(element, "redirect_ips"),
            RedirectDomains = ReadRules(element, "redirect_domains")
        };
        if (!legacy && element.TryGetProperty("control_ports", out var control))
            result.ControlPorts = JsonSerializer.Deserialize<PortRange>(control.GetRawText()) ?? throw Invalid();
        return result;
    }

    public static void Validate(ClientConfig config)
    {
        if (config.Protocol != 2 || config.LogLevel is not ("none" or "error" or "warning" or "info" or "debug") ||
            config.TunnelMaxMss is < 1 or > 65535 || config.Servers == null || config.Servers.Count > 1000) throw Invalid();
        if (config.RoutingMode is not ("split" or "full") || config.FullRoutingProfileId == null ||
            (config.RoutingMode == "split" && config.FullRoutingProfileId.Length != 0)) throw Invalid();
        foreach (var server in config.Servers)
        {
            if (server == null || server.Protocol != 2 || string.IsNullOrWhiteSpace(server.ServerIp) ||
                server.ServerIp.Length > 253 || server.ConnectionName == null || server.ControlPorts == null ||
                server.ControlPorts.Start is < 1 or > 65535 || server.ControlPorts.End < server.ControlPorts.Start ||
                server.ControlPorts.End > 65535) throw Invalid();
            if (server.RequiresInvitation)
            {
                if (!string.IsNullOrEmpty(server.ProfileId)) throw Invalid();
            }
            else if (string.IsNullOrEmpty(server.ProfileId) || server.ProfileId.Length > 128 ||
                server.ProfileId.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) throw Invalid();
            if (server.RedirectIps != null && server.RedirectIps.Any(value => value == null || !IsValidIpRule(value)))
                throw new InvalidDataException("Правило IP должно содержать IPv4-адрес или диапазон IPv4 от меньшего адреса к большему.");
            foreach (var rules in new[] { server.RedirectProcesses, server.RedirectIps, server.RedirectDomains })
                if (rules == null || rules.Count > 10000 || rules.Any(string.IsNullOrWhiteSpace)) throw Invalid();
        }
        if (config.RoutingMode == "full" && (config.FullRoutingProfileId.Length == 0 ||
            config.Servers.Any(server => server.Enabled && server.RequiresInvitation) ||
            config.Servers.Count(server => server.Enabled && server.ProfileId == config.FullRoutingProfileId) != 1)) throw Invalid();
    }

    public static bool IsValidIpRule(string value)
    {
        var endpoints = value.Split('-');
        if (endpoints.Length is < 1 or > 2 || !TryReadIpv4(endpoints[0], out uint first)) return false;
        return endpoints.Length == 1 || TryReadIpv4(endpoints[1], out uint last) && first <= last;
    }

    private static bool TryReadIpv4(string value, out uint address)
    {
        address = 0;
        var octets = value.Split('.');
        if (octets.Length != 4) return false;
        foreach (string octet in octets)
        {
            if (octet.Length is < 1 or > 3 || octet.Length > 1 && octet[0] == '0' ||
                octet.Any(c => c is < '0' or > '9') || !byte.TryParse(octet, out byte number)) return false;
            address = (address << 8) | number;
        }
        return true;
    }

    private static int ReadVersion(JsonElement element) => element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var value) && value is 1 or 2 ? value : throw Invalid();

    private static bool ReadBoolean(JsonElement element, string name, bool fallback) =>
        !element.TryGetProperty(name, out var value) ? fallback :
        value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : throw Invalid();

    private static string ReadString(JsonElement element, string name, string fallback) =>
        !element.TryGetProperty(name, out var value) ? fallback : value.ValueKind == JsonValueKind.String ? value.GetString()! : throw Invalid();

    private static List<string> ReadRules(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)) return new();
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 10000) throw Invalid();
        return value.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String ? item.GetString()! : throw Invalid()).ToList();
    }

    private static void CheckObject(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Invalid();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject()) if (!names.Add(property.Name)) throw Invalid();
    }

    private static InvalidDataException Invalid() => new("Некорректная или неподдерживаемая конфигурация. Исходные настройки сохранены.");
}
