using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace MIGA_Agent.Models;

public sealed record ProtocolV2Invitation(string Host, int FirstPort, int LastPort)
{
    public static ProtocolV2Invitation Parse(string value)
    {
        if (value.Length > 4096 || !value.StartsWith("miga2:", StringComparison.Ordinal))
            throw new InvalidDataException("Приглашение MIGA повреждено или имеет неподдерживаемый формат.");
        try
        {
            using var document = JsonDocument.Parse(Decode(value[6..]));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!fields.Add(property.Name)) throw new InvalidDataException();
            string[] expected = ["v", "host", "ports", "server_key", "server_secret", "client_id", "client_secret"];
            if (!fields.SetEquals(expected) || root.GetProperty("v").GetInt32() != 2)
                throw new InvalidDataException();
            var host = root.GetProperty("host").GetString() ?? "";
            if (host.Length is 0 or > 253 || host.Any(char.IsWhiteSpace) || host.Contains('\0'))
                throw new InvalidDataException();
            if (IPAddress.TryParse(host, out var address))
            {
                if (address.AddressFamily != AddressFamily.InterNetwork) throw new InvalidDataException();
            }
            else if (Uri.CheckHostName(host) != UriHostNameType.Dns) throw new InvalidDataException();
            var ports = root.GetProperty("ports");
            if (ports.ValueKind != JsonValueKind.Array || ports.GetArrayLength() != 2)
                throw new InvalidDataException();
            int first = ports[0].GetInt32(), last = ports[1].GetInt32();
            if (first < 1024 || last > 65535 || first > last) throw new InvalidDataException();
            foreach (var name in expected.Skip(3))
                if (Decode(root.GetProperty(name).GetString() ?? "").Length != (name == "client_id" ? 16 : 32))
                    throw new InvalidDataException();
            return new(host, first, last);
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or KeyNotFoundException or InvalidDataException or OverflowException)
        {
            throw new InvalidDataException("Приглашение MIGA повреждено или имеет неподдерживаемый формат.");
        }
    }

    private static byte[] Decode(string value)
    {
        if (value.Length == 0 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) || value.Length % 4 == 1)
            throw new FormatException();
        var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value)
            throw new FormatException();
        return bytes;
    }
}
