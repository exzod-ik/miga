using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using MIGA_Agent.Models;

namespace MIGA_Agent.Services;

public static class InvitationHandoff
{
    private const int ErrorCancelled = 1223;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    public static Task SendAsync(string invitation) => SendAsync(invitation, Process.Start);

    internal static async Task SendAsync(string invitation, Func<ProcessStartInfo, Process?> startClient)
    {
        ProtocolV2Invitation.Parse(invitation);
        string executable = Path.Combine(AppContext.BaseDirectory, "MIGA Client.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("MIGA Client не установлен. Сохраните приглашение в файл или покажите QR.");
        string id = Guid.NewGuid().ToString("N");
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new IOException("Не удалось определить пользователя Windows.");
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        using var pipe = NamedPipeServerStreamAcl.Create("MigaInvitation-" + id, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory,
            ArgumentList = { "--invitation-pipe", id }
        };
        Process? started;
        try { started = await Task.Run(() => startClient(startInfo)); }
        catch (Win32Exception error) when (error.NativeErrorCode == ErrorCancelled)
        {
            throw new IOException("Запуск MIGA Client с повышенными правами отменён.", error);
        }
        using var child = started ?? throw new IOException("Не удалось открыть MIGA Client.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        child.EnableRaisingEvents = true;
        EventHandler exited = (_, _) => { try { timeout.Cancel(); } catch (ObjectDisposedException) { } };
        child.Exited += exited;
        try
        {
            if (child.HasExited) timeout.Cancel();
            await pipe.WaitForConnectionAsync(timeout.Token);
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint processId) || processId != child.Id)
                throw new IOException("Неверный получатель приглашения.");
            VerifyPeer(processId, executable);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true);
            await writer.WriteLineAsync(invitation.AsMemory(), timeout.Token);
            await writer.FlushAsync(timeout.Token);
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 128, true);
            var ack = new char[1];
            if (await reader.ReadAsync(ack.AsMemory(), timeout.Token) != 1 || ack[0] != '1')
                throw new IOException("MIGA Client не подтвердил получение. Закройте уже открытое окно Client и повторите действие.");
        }
        finally { child.Exited -= exited; }
    }

    public static async Task<string> ReceiveAsync(string id)
    {
        if (!Guid.TryParseExact(id, "N", out _) || id.Length != 32) throw new InvalidDataException("Неверный канал приглашения.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var pipe = new NamedPipeClientStream(".", "MigaInvitation-" + id, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
        await pipe.ConnectAsync(timeout.Token);
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint processId))
            throw new IOException("Не удалось проверить отправителя приглашения.");
        VerifyPeer(processId, Path.Combine(AppContext.BaseDirectory, "MIGA Admin.exe"));
        using var reader = new StreamReader(pipe, new UTF8Encoding(false, true), false, 4096, true);
        var value = new StringBuilder();
        var buffer = new char[1];
        while (value.Length <= 4096)
        {
            if (await reader.ReadAsync(buffer.AsMemory(), timeout.Token) == 0) throw new IOException("Отправитель закрыл канал.");
            if (buffer[0] == '\n')
            {
                string invitation = value.ToString().TrimEnd('\r');
                ProtocolV2Invitation.Parse(invitation);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 128, true);
                await writer.WriteAsync("1".AsMemory(), timeout.Token);
                await writer.FlushAsync(timeout.Token);
                return invitation;
            }
            value.Append(buffer[0]);
        }
        throw new InvalidDataException("Приглашение слишком большое.");
    }

    internal static void VerifyPeer(uint processId, string executable)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        using var current = Process.GetCurrentProcess();
        var image = new StringBuilder(32768);
        int length = image.Capacity;
        if (process.IsInvalid || !ProcessIdToSessionId(processId, out uint sessionId) || sessionId != current.SessionId ||
            !QueryFullProcessImageName(process, 0, image, ref length) ||
            !string.Equals(Path.GetFullPath(image.ToString()), Path.GetFullPath(executable), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Приложение приглашений не прошло проверку.");
        if (!OpenProcessToken(process, TokenQuery, out var token)) throw new IOException("Не удалось проверить владельца приложения.");
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
        using (var own = WindowsIdentity.GetCurrent())
            if (identity.User is not { } peer || own.User is not { } currentUser || !peer.Equals(currentUser))
                throw new IOException("Приложение запущено другим пользователем.");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder executable, ref int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
}
