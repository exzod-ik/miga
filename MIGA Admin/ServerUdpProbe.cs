using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace MIGA_Agent.Services;

internal static class ServerUdpProbe
{
    internal const int PacketCount = 5;
    private const int TokenLength = 16;
    private const byte ReplyFlag = 0x80;

    private const string RemoteSetup = """
        set -eu
        if ! command -v python3 >/dev/null || ! command -v timeout >/dev/null; then
            printf '%s\n' 'MIGA-UDP-ERROR dependency'
            exit 0
        fi
        umask 077
        probe=''
        runner=''
        cleanup() {
            if [ -n "$runner" ]; then
                kill "$runner" 2>/dev/null || :
                wait "$runner" 2>/dev/null || :
            fi
            if [ -n "$probe" ]; then rm -f -- "$probe"; fi
        }
        trap cleanup EXIT
        trap 'exit 130' HUP INT TERM
        probe=$(mktemp "${TMPDIR:-/tmp}/miga-udp.XXXXXXXXXX")
        cat > "$probe" <<'MIGA_UDP_SCRIPT'
        import errno
        import os
        import signal
        import socket
        import sys
        import time

        def interrupt(signum, frame):
            raise SystemExit(130)

        def probe():
            port = int(sys.argv[1])
            token = bytes.fromhex(sys.argv[2])
            count = int(sys.argv[3])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.bind(('0.0.0.0', port))
                except OSError as error:
                    reason = 'busy' if error.errno == errno.EADDRINUSE else 'bind'
                    print('MIGA-UDP-ERROR ' + reason, flush=True)
                    return

                ssh_fields = os.environ.get('SSH_CONNECTION', '').split()
                ssh_address = ssh_fields[2] if len(ssh_fields) == 4 else '-'
                print(f'MIGA-UDP-READY {udp.getsockname()[1]} {ssh_address}', flush=True)
                deadline = time.monotonic() + 3
                endpoint = None
                received = set()
                while len(received) < count:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    udp.settimeout(remaining)
                    try:
                        data, source = udp.recvfrom(len(token) + 2)
                    except socket.timeout:
                        break
                    if len(data) != len(token) + 1 or data[0] >= count or data[1:] != token:
                        continue
                    if endpoint is None:
                        endpoint = source
                    if endpoint == source:
                        received.add(data[0])

                sent = 0
                if endpoint is not None:
                    udp.settimeout(0.25)
                    for sequence in range(count):
                        if sequence:
                            time.sleep(0.1)
                        try:
                            sent += udp.sendto(bytes([0x80 | sequence]) + token, endpoint) == len(token) + 1
                        except OSError:
                            pass
                print(f'MIGA-UDP-RESULT {len(received)} {sent}', flush=True)

        try:
            for name in ('SIGHUP', 'SIGINT', 'SIGTERM'):
                sig = getattr(signal, name, None)
                if sig is not None:
                    signal.signal(sig, interrupt)
            probe()
        finally:
            try:
                os.unlink(__file__)
            except FileNotFoundError:
                pass
        MIGA_UDP_SCRIPT
        """;

    internal sealed record Result(IPAddress Address, ushort Port, int ClientSent, int ServerReceived, int ServerSent, int ClientReceived);

    internal sealed class ProbeException(string message) : Exception(message);

    internal static async Task<Result> CheckAsync(ISshManager ssh, string host, ushort port, CancellationToken cancellationToken)
    {
        if (port is > 0 and < 1024)
            throw new ArgumentOutOfRangeException(nameof(port));

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        var addresses = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, deadline.Token);
        if (addresses.Length == 0)
            throw new ProbeException("У сервера нет доступного IPv4-адреса.");
        IPAddress? address = null;

        var token = RandomNumberGenerator.GetBytes(TokenLength);
        string command = RemoteSetup.ReplaceLineEndings("\n") +
            FormattableString.Invariant($"\ntimeout -k 1s 8s python3 -I \"$probe\" {port} {Convert.ToHexString(token)} {PacketCount} &\nrunner=$!\nstatus=0\nwait \"$runner\" || status=$?\nrunner=''\nexit \"$status\"");
        ushort boundPort = 0;
        int sent = 0, received = 0;
        string response = await ssh.ExecuteCheckedAsync(command, TimeSpan.FromSeconds(10), async (line, active) =>
        {
            if (line.StartsWith("MIGA-UDP-ERROR ", StringComparison.Ordinal))
                throw ProbeFailure(line["MIGA-UDP-ERROR ".Length..]);

            string[] ready = line.Split(' ');
            if (ready.Length != 3 || ready[0] != "MIGA-UDP-READY" ||
                !ushort.TryParse(ready[1], NumberStyles.None, CultureInfo.InvariantCulture, out boundPort) ||
                boundPort < 1024 || (port != 0 && port != boundPort))
                throw new ProbeException("SSH не подтвердил запуск UDP-проверки.");

            if (addresses.Length == 1)
                address = addresses[0];
            else if (IPAddress.TryParse(ready[2], out var sshAddress) && addresses.Contains(sshAddress))
                address = sshAddress;
            else
                throw new ProbeException("У имени сервера несколько IPv4-адресов. Переподключитесь по IPv4-адресу нужного VPS.");

            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            await udp.ConnectAsync(new IPEndPoint(address, boundPort), active);
            var packet = new byte[TokenLength + 1];
            token.CopyTo(packet, 1);
            for (byte sequence = 0; sequence < PacketCount; ++sequence)
            {
                if (sequence != 0) await Task.Delay(TimeSpan.FromMilliseconds(100), active);
                packet[0] = sequence;
                try
                {
                    if (await udp.SendAsync(packet, SocketFlags.None, active) == packet.Length) ++sent;
                }
                catch (SocketException error) when (IsUnreachable(error)) { }
            }

            using var receiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(active);
            receiveDeadline.CancelAfter(TimeSpan.FromSeconds(5));
            var replies = new HashSet<byte>();
            var buffer = new byte[65536];
            try
            {
                while (replies.Count < PacketCount)
                {
                    var length = await udp.ReceiveAsync(buffer, SocketFlags.None, receiveDeadline.Token);
                    if (length == packet.Length && buffer[0] >= ReplyFlag && buffer[0] < ReplyFlag + PacketCount &&
                        buffer.AsSpan(1, TokenLength).SequenceEqual(token))
                        replies.Add(buffer[0]);
                }
            }
            catch (OperationCanceledException) when (!active.IsCancellationRequested) { }
            catch (SocketException error) when (IsUnreachable(error)) { }
            received = replies.Count;
        }, deadline.Token);

        string[] fields = response.Trim().Split(' ');
        if (address is null || boundPort == 0 || fields.Length != 3 || fields[0] != "MIGA-UDP-RESULT" ||
            !TryCount(fields[1], out int serverReceived) || !TryCount(fields[2], out int serverSent) ||
            serverReceived > sent || received > serverSent || (serverReceived == 0 && serverSent != 0))
            throw new ProbeException("Получен неподдерживаемый результат UDP-проверки.");

        return new Result(address, boundPort, sent, serverReceived, serverSent, received);
    }

    private static bool TryCount(string text, out int count) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out count) && count <= PacketCount;

    private static bool IsUnreachable(SocketException error) =>
        error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused;

    private static ProbeException ProbeFailure(string reason) => new(reason switch
    {
        "dependency" => "Для UDP-проверки на VPS нужны python3 и timeout.",
        "busy" => "Выбранный UDP-порт занят. Укажите другой порт или 0 для автоматического выбора.",
        "bind" => "VPS не смог открыть выбранный UDP-порт.",
        _ => "На VPS не удалось запустить UDP-проверку."
    });
}
