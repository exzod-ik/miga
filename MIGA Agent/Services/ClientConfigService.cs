using Microsoft.Win32;
using MIGA_Agent.Models;
using System;
using System.IO;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace MIGA_Agent.Services
{
    public class ClientConfigService : IClientConfigService
    {
        private string _configFilePath;

        public string ConfigFilePath
        {
            get => _configFilePath;
            set => _configFilePath = value;
        }

        public ClientConfigService()
        {
            _configFilePath = GetConfigFilePath();
        }

        private string GetConfigFilePath()
        {
            string? servicePath = GetServiceExecutablePath("MigaClient");
            if (string.IsNullOrEmpty(servicePath))
                throw new InvalidOperationException("Служба MigaClient не установлена. Пожалуйста, переустановите приложение.");

            string? directory = Path.GetDirectoryName(servicePath);
            if (string.IsNullOrEmpty(directory))
                throw new InvalidOperationException("Не удалось определить директорию службы MigaClient.");

            return Path.Combine(directory, "config.json");
        }

        private string? GetServiceExecutablePath(string serviceName)
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}"))
                {
                    if (key?.GetValue("ImagePath") is string imagePath)
                    {
                        imagePath = imagePath.Trim();

                        // 1. Если путь в кавычках
                        if (imagePath.StartsWith("\""))
                        {
                            int endQuote = imagePath.IndexOf('\"', 1);
                            if (endQuote > 0)
                            {
                                string path = imagePath.Substring(1, endQuote - 1);
                                if (File.Exists(path))
                                    return path;
                            }
                        }
                        else
                        {
                            // 2. Без кавычек: пробуем собрать существующий файл, объединяя части
                            var parts = imagePath.Split(' ');
                            for (int i = 1; i <= parts.Length; i++)
                            {
                                string candidate = string.Join(" ", parts.Take(i));
                                if (File.Exists(candidate))
                                    return candidate;
                            }
                            // 3. Запасной вариант: берём до первого пробела
                            int firstSpace = imagePath.IndexOf(' ');
                            if (firstSpace > 0)
                                return imagePath.Substring(0, firstSpace);
                            else
                                return imagePath;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        public async Task<ClientConfig> LoadAsync()
        {
            if (!File.Exists(ConfigFilePath))
            {
                var defaultConfig = new ClientConfig();
                await SaveAsync(defaultConfig);
                return defaultConfig;
            }

            string json = await File.ReadAllTextAsync(ConfigFilePath);
            var config = JsonSerializer.Deserialize<ClientConfig>(json);
            return config ?? new ClientConfig();
        }

        public async Task SaveAsync(ClientConfig config)
        {
            string directory = Path.GetDirectoryName(ConfigFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            string json = JsonSerializer.Serialize(config, options);
            await File.WriteAllTextAsync(ConfigFilePath, json);
        }
    }
}
