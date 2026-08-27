using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    /// <summary>
    /// Настройки одного сервера внутри клиентского конфига (элемент массива servers).
    /// </summary>
    public class ServerEntry
    {
        [JsonPropertyName("server_ip")]
        public string ServerIp { get; set; } = string.Empty;

        [JsonPropertyName("server_ports")]
        public PortRange ServerPorts { get; set; } = new PortRange();

        [JsonPropertyName("encryption")]
        public EncryptionKeys Encryption { get; set; } = new EncryptionKeys();

        [JsonPropertyName("redirect_processes")]
        public List<string> RedirectProcesses { get; set; } = new List<string>();

        [JsonPropertyName("redirect_ips")]
        public List<string> RedirectIps { get; set; } = new List<string>();

        [JsonPropertyName("redirect_domains")]
        public List<string> RedirectDomains { get; set; } = new List<string>();
    }
}
