using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using MIGA_Agent.Models;

namespace MIGA_Agent.Services;

public sealed class ProtocolV2ProfileService
{
    public static async Task EnsureReadyAsync(ILocalServiceManager service)
    {
        var config = new ClientConfigService();
        if (!File.Exists(config.ConfigFilePath))
            await config.SaveAsync(new ClientConfig());
        await Task.Run(service.Start);
    }

    public async Task<string> ImportAsync(string invitation, CancellationToken cancellationToken = default)
    {
        ProtocolV2Invitation.Parse(invitation);
        using var reply = await RequestAsync(JsonSerializer.Serialize(new { operation = "import", invitation }), TimeSpan.FromSeconds(15), cancellationToken);
        if (!reply.RootElement.GetProperty("ok").GetBoolean())
            throw new IOException("Служба отклонила импорт приглашения.");
        string id = reply.RootElement.GetProperty("profile_id").GetString() ?? "";
        if (id.Length is 0 or > 128 || id.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new IOException("Неверная ссылка на профиль службы.");
        return id;
    }
    public async Task<string> ExportAsync(string profileId, CancellationToken cancellationToken = default)
    {
        if (profileId.Length != 32 || profileId.Any(c => !char.IsAsciiHexDigitLower(c)))
            throw new InvalidDataException("Неверная ссылка на профиль.");
        using var reply = await RequestAsync(JsonSerializer.Serialize(new { operation = "export", profile_id = profileId }), TimeSpan.FromSeconds(5), cancellationToken);
        if (!reply.RootElement.GetProperty("ok").GetBoolean())
            throw new IOException("Сохранённое приглашение недоступно.");
        string value = reply.RootElement.GetProperty("invitation").GetString() ?? "";
        ProtocolV2Invitation.Parse(value);
        return value;
    }

    public async Task<System.Text.Json.Nodes.JsonObject> OpenDiagnosticsAsync(string profileId, CancellationToken cancellationToken = default)
    {
        using var reply = await RequestAsync(JsonSerializer.Serialize(new { operation = "diagnostics", profile_id = profileId }), TimeSpan.FromSeconds(14), cancellationToken);
        if (!reply.RootElement.GetProperty("ok").GetBoolean())
            throw new IOException("Серверная диагностика недоступна. Дождитесь подключения и убедитесь, что сервер обновлён.");
        return System.Text.Json.Nodes.JsonNode.Parse(reply.RootElement.GetRawText())!.AsObject();
    }
    public async Task<string> GetStatusAsync(string profileId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(profileId) || profileId.Length > 128 || profileId.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new InvalidDataException("Неверная ссылка на профиль.");
        using var reply = await RequestAsync(JsonSerializer.Serialize(new { operation = "status", profile_id = profileId }), TimeSpan.FromSeconds(5), cancellationToken);
        if (!reply.RootElement.GetProperty("ok").GetBoolean())
            throw new IOException("Профиль не настроен в работающей конфигурации службы.");
        string state = reply.RootElement.GetProperty("state").GetString() ?? "";
        if (state is not ("ready" or "connecting" or "unavailable" or "recovering"))
            throw new IOException("Неизвестное состояние подключения.");
        return state;
    }

    private static async Task<JsonDocument> RequestAsync(string request, TimeSpan duration, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(duration);
        using var pipe = new NamedPipeClientStream(".", "MigaProfiles-v2", PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(timeout.Token);
        VerifyServerIdentity(pipe);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        await writer.WriteLineAsync(request.AsMemory(), timeout.Token);
        var response = new StringBuilder();
        var buffer = new char[1];
        while (response.Length <= 4096)
        {
            if (await reader.ReadAsync(buffer.AsMemory(), timeout.Token) == 0) throw new IOException("Служба закрыла канал импорта.");
            if (buffer[0] == '\n') break;
            response.Append(buffer[0]);
        }
        if (response.Length > 4096) throw new IOException("Неверный ответ службы.");
        return JsonDocument.Parse(response.ToString());
    }

    private static void VerifyServerIdentity(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint pipeProcess) || pipeProcess == 0)
            throw new IOException("Не удалось проверить службу импорта профиля.");
        IntPtr manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new IOException("Не удалось проверить службу импорта профиля.");
        try
        {
            IntPtr service = OpenService(manager, "MigaClient", 4);
            if (service == IntPtr.Zero) throw new IOException("Служба импорта профиля не найдена.");
            try
            {
                if (!QueryServiceStatusEx(service, 0, out ServiceStatusProcess status, Marshal.SizeOf<ServiceStatusProcess>(), out _) || status.CurrentState != 4 || status.ProcessId != pipeProcess)
                    throw new IOException("Канал импорта не принадлежит службе MigaClient.");
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int informationLevel, out ServiceStatusProcess status, int size, out int required);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

}
