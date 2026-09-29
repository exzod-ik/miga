using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace MIGA_Agent.Models
{
    /// <summary>Формат обмена подключением к серверу для QR-кода и файла.</summary>
    public sealed class ServerSharePayload
    {
        public const int MaxJsonLength = 16 * 1024;

        public string Address { get; }
        public int FirstPort { get; }
        public int LastPort { get; }
        public string XorKey { get; }
        public string SwapKey { get; }

        private ServerSharePayload(string address, int firstPort, int lastPort, string xorKey, string swapKey)
        {
            Address = address;
            FirstPort = firstPort;
            LastPort = lastPort;
            XorKey = xorKey;
            SwapKey = swapKey;
        }

        public static ServerSharePayload Create(string? address, int firstPort, int lastPort, string? xorKey, string? swapKey)
        {
            address = address?.Trim() ?? string.Empty;
            xorKey ??= string.Empty;
            swapKey ??= string.Empty;
            var octets = address.Split('.');
            if (octets.Length != 4 || octets.Any(part => part.Length is < 1 or > 3
                    || !part.All(char.IsAsciiDigit) || !byte.TryParse(part, out _))
                || !IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork
                || firstPort < 1 || firstPort > 65535 || lastPort < firstPort || lastPort > 65535
                || !IsBase64OfLength(xorKey, 128) || !IsBase64OfLength(swapKey, 8))
            {
                throw new InvalidDataException("Проверьте IPv4-адрес, диапазон портов и ключи сервера.");
            }

            return new ServerSharePayload(address, firstPort, lastPort, xorKey, swapKey);
        }

        public static ServerSharePayload Parse(string json)
        {
            if (json.Length > MaxJsonLength)
                throw new InvalidDataException("Файл сервера слишком большой.");

            try
            {
                using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String
                    || type.GetString() != "miga-server"
                    || !root.TryGetProperty("version", out var version) || !version.TryGetInt32(out var number) || number != 1)
                {
                    throw new InvalidDataException("Это не файл сервера M.I.G.A. версии 1.");
                }

                if (!root.TryGetProperty("address", out var address) || address.ValueKind != JsonValueKind.String
                    || !root.TryGetProperty("ports", out var ports) || ports.ValueKind != JsonValueKind.Array
                    || ports.GetArrayLength() != 2
                    || !ports[0].TryGetInt32(out var firstPort) || !ports[1].TryGetInt32(out var lastPort)
                    || !root.TryGetProperty("xor", out var xor) || xor.ValueKind != JsonValueKind.String
                    || !root.TryGetProperty("swap", out var swap) || swap.ValueKind != JsonValueKind.String)
                {
                    throw new InvalidDataException("В файле отсутствуют адрес, порты или ключи сервера.");
                }

                return Create(address.GetString()!, firstPort, lastPort, xor.GetString()!, swap.GetString()!);
            }
            catch (JsonException)
            {
                throw new InvalidDataException("Файл сервера содержит некорректный JSON.");
            }
            catch (InvalidOperationException)
            {
                throw new InvalidDataException("В файле сервера указан неверный формат данных.");
            }
        }

        public string ToJson(bool indented = false) => JsonSerializer.Serialize(new
        {
            type = "miga-server",
            version = 1,
            address = Address,
            ports = new[] { FirstPort, LastPort },
            xor = XorKey,
            swap = SwapKey
        }, new JsonSerializerOptions { WriteIndented = indented });

        public ServerEntry ToServerEntry() => new()
        {
            ServerIp = Address,
            ServerPorts = new PortRange { Start = FirstPort, End = LastPort },
            Encryption = new EncryptionKeys { XorKey = XorKey, SwapKey = SwapKey }
        };

        private static bool IsBase64OfLength(string value, int length)
        {
            try { return Convert.FromBase64String(value).Length == length; }
            catch (FormatException) { return false; }
        }
    }
}
