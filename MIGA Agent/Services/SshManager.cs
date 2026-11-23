using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;

namespace MIGA_Agent.Services
{
    public class SshManager : ISshManager
    {
        private SshClient? _client;
        private byte[]? _hostKey;

        public bool IsConnected => _client?.IsConnected == true;

        public async Task ConnectAsync(string host, int port, string username, string password)
        {
            await Task.Run(() =>
            {
                _client?.Dispose();
                _client = new SshClient(host, port, username, password);
                _client.HostKeyReceived += (_, e) =>
                {
                    var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MIGA", "SshHosts");
                    Directory.CreateDirectory(folder);
                    var id = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{host}:{port}")));
                    var path = Path.Combine(folder, id);
                    if (!File.Exists(path))
                    {
                        var temporary = path + "." + Guid.NewGuid().ToString("N");
                        try
                        {
                            File.WriteAllBytes(temporary, e.HostKey);
                            try { File.Move(temporary, path); }
                            catch (IOException) when (File.Exists(path)) { }
                        }
                        finally { File.Delete(temporary); }
                    }
                    e.CanTrust = File.ReadAllBytes(path).AsSpan().SequenceEqual(e.HostKey);
                    if (!e.CanTrust) throw new InvalidOperationException($"Ключ SSH {host} изменился. Сверьте ключ сервер перед заменой записи {path}.");
                    _hostKey = e.HostKey.ToArray();
                };
                _client.Connect();
            });
        }

        public void Disconnect()
        {
            _client?.Disconnect();
            _client?.Dispose();
            _client = null;
        }

        public async Task<string> ExecuteCommandAsync(string command)
        {
            if (!IsConnected)
                throw new InvalidOperationException("SSH not connected");

            return await Task.Run(() =>
            {
                using var cmd = _client!.CreateCommand(command);
                string result = cmd.Execute();
                return result;
            });
        }

        public async Task UploadFileAsync(Stream localStream, string remotePath)
        {
            if (!IsConnected)
                throw new InvalidOperationException("SSH not connected");

            await Task.Run(() =>
            {
                using var sftp = OpenSftp();
                sftp.UploadFile(localStream, remotePath);
            });
        }

        public async Task UploadFileAsync(string localPath, string remotePath)
        {
            using var stream = File.OpenRead(localPath);
            await UploadFileAsync(stream, remotePath);
        }

        public async Task DownloadFileAsync(string remotePath, Stream localStream)
        {
            if (!IsConnected)
                throw new InvalidOperationException("SSH not connected");

            await Task.Run(() =>
            {
                using var sftp = OpenSftp();
                sftp.DownloadFile(remotePath, localStream);
            });
        }

        public async Task DownloadFileAsync(string remotePath, string localPath)
        {
            using var stream = File.Create(localPath);
            await DownloadFileAsync(remotePath, stream);
        }

        public void Dispose()
        {
            Disconnect();
        }

        private SftpClient OpenSftp()
        {
            var connection = _client ?? throw new InvalidOperationException("SSH отключён.");
            var key = _hostKey ?? throw new InvalidOperationException("Нет ключа SSH-соединения.");
            var sftp = new SftpClient(connection.ConnectionInfo);
            sftp.HostKeyReceived += (_, e) => e.CanTrust = key.AsSpan().SequenceEqual(e.HostKey);
            try { sftp.Connect(); return sftp; }
            catch { sftp.Dispose(); throw; }
        }

        public async Task<string> ExecuteCheckedAsync(string command, TimeSpan? timeout = null)
        {
            var connection = _client;
            if (connection?.IsConnected != true) throw new Renci.SshNet.Common.SshConnectionException("SSH отключён.");
            using var cmd = connection.CreateCommand(command);
            if (timeout.HasValue) cmd.CommandTimeout = timeout.Value;
            await cmd.ExecuteAsync();
            if (cmd.ExitStatus != 0)
                throw new SshCommandFailure(cmd.Result, cmd.ExitStatus, cmd.Error);
            return cmd.Result;
        }

        public Task<string> ExecuteCheckedAsync(string command, TimeSpan timeout,
            Func<string, CancellationToken, Task> onFirstLine, CancellationToken cancellationToken) => Task.Run(async () =>
        {
            var connection = _client;
            if (connection?.IsConnected != true) throw new Renci.SshNet.Common.SshConnectionException("SSH отключён.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);
            using var cmd = connection.CreateCommand(command);
            var execution = cmd.ExecuteAsync(deadline.Token);
            using var reader = new StreamReader(cmd.OutputStream, leaveOpen: true);
            try
            {
                string? firstLine = await reader.ReadLineAsync(deadline.Token);
                if (firstLine != null) await onFirstLine(firstLine, deadline.Token);
                await execution;
                var remaining = await reader.ReadToEndAsync(deadline.Token);
                if (cmd.ExitStatus != 0)
                    throw new SshCommandFailure(firstLine + "\n" + remaining, cmd.ExitStatus, cmd.Error);
                return remaining;
            }
            finally
            {
                if (!execution.IsCompleted) deadline.Cancel();
                try { await execution; }
                catch (Exception) { }
            }
        }, cancellationToken);
    }
}
