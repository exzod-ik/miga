using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    public class ClientConfig
    {
        [JsonPropertyName("server_ip")]
        public string ServerIp { get; set; } = "127.0.0.1";

        [JsonPropertyName("server_ports")]
        public PortRange ServerPorts { get; set; } = new PortRange();

        [JsonPropertyName("log_level")]
        public string LogLevel { get; set; } = "none";

        [JsonPropertyName("encryption")]
        public EncryptionKeys Encryption { get; set; } = new EncryptionKeys();

        [JsonPropertyName("redirect_processes")]
        public List<string> RedirectProcesses { get; set; } = new List<string>();

        [JsonPropertyName("redirect_ips")]
        public List<string> RedirectIps { get; set; } = new List<string>();
    }
}
