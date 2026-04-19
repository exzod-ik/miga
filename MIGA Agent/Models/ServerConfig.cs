using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    public class ServerConfig
    {
        [JsonPropertyName("log_level")]
        public string LogLevel { get; set; } = "none";
        [JsonPropertyName("client_ports")]
        public PortRange ClientPorts { get; set; } = new PortRange();
        [JsonPropertyName("encryption")]
        public EncryptionKeys Encryption { get; set; } = new EncryptionKeys();
    }
}
