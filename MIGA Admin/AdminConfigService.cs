using System.IO;
using System.Text.Json;

namespace MIGA_Agent.Services;

public sealed record ManagedServerEntry(string Name, string Host, string User);

public sealed class AdminConfigService
{
    public string FilePath { get; }
    public AdminConfigService(string? filePath = null)
    {
        FilePath = filePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MIGA", "admin-servers.json");
    }

    public FileStream AcquireEditorLock()
    {
        var path = Path.GetFullPath(FilePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        return new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public async Task<List<ManagedServerEntry>> LoadAsync(string? legacyPath = null)
    {
        if (File.Exists(FilePath))
        {
            var entries = JsonSerializer.Deserialize<List<ManagedServerEntry>>(await File.ReadAllTextAsync(FilePath)) ?? throw new InvalidDataException("Повреждён список серверов.");
            if (entries.Any(entry => entry == null || entry.Name == null || entry.Host == null || entry.User == null || entry.Host.Contains('\0') || entry.User.Contains('\0')))
                throw new InvalidDataException("Повреждён список серверов.");
            return entries;
        }
        var result = new List<ManagedServerEntry>();
        if (legacyPath != null && File.Exists(legacyPath))
        {
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(legacyPath));
            var root = document.RootElement;
            IEnumerable<JsonElement> servers = root.TryGetProperty("servers", out var list) ? list.EnumerateArray() : new[] { root };
            foreach (var server in servers)
            {
                string Text(params string[] names)
                {
                    foreach (string name in names)
                        if (server.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String) return value.GetString() ?? "";
                    return "";
                }
                string host = Text("server_ip", "host");
                if (!string.IsNullOrWhiteSpace(host))
                    result.Add(new(Text("connection_name", "name"), host, Text("server_ssh_user", "ssh_user") is { Length: > 0 } user ? user : "root"));
            }
        }
        await SaveAsync(result);
        return result;
    }

    public async Task SaveAsync(IEnumerable<ManagedServerEntry> servers)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
        string temporary = FilePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(servers, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, FilePath, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
