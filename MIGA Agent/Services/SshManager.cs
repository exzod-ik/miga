using System;
using System.IO;
using System.Threading.Tasks;
using Renci.SshNet;

namespace MIGA_Agent.Services
{
    public class SshManager : ISshManager
    {
        private SshClient? _client;

        public bool IsConnected => _client?.IsConnected == true;

        public async Task ConnectAsync(string host, int port, string username, string password)
        {
            await Task.Run(() =>
            {
                _client?.Dispose();
                _client = new SshClient(host, port, username, password);
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
                using var scp = new ScpClient(_client.ConnectionInfo);
                scp.Connect();
                scp.Upload(localStream, remotePath);
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
                using var scp = new ScpClient(_client.ConnectionInfo);
                scp.Connect();
                scp.Download(remotePath, localStream);
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
    }
}