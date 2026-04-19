using System;
using System.IO;
using System.Threading.Tasks;

namespace MIGA_Agent.Services
{
    public interface ISshManager : IDisposable
    {
        bool IsConnected { get; }

        Task ConnectAsync(string host, int port, string username, string password);
        void Disconnect();

        Task<string> ExecuteCommandAsync(string command);
        Task UploadFileAsync(Stream localStream, string remotePath);
        Task UploadFileAsync(string localPath, string remotePath);
        Task DownloadFileAsync(string remotePath, Stream localStream);
        Task DownloadFileAsync(string remotePath, string localPath);
    }
}