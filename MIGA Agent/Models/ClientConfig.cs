using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    /// <summary>
    /// Корневая структура клиентского конфига: log_level, tunnel_max_mss и список серверов.
    /// </summary>
    public class ClientConfig
    {
        [JsonPropertyName("log_level")]
        public string LogLevel { get; set; } = "none";

        [JsonPropertyName("tunnel_max_mss")]
        public int TunnelMaxMss { get; set; } = 1400;

        [JsonPropertyName("servers")]
        public List<ServerEntry> Servers { get; set; } = new List<ServerEntry>();
    }
}
