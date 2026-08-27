using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    /// <summary>
    /// Корневая структура клиентского конфига: log_level + список серверов.
    /// </summary>
    public class ClientConfig
    {
        [JsonPropertyName("log_level")]
        public string LogLevel { get; set; } = "none";

        [JsonPropertyName("servers")]
        public List<ServerEntry> Servers { get; set; } = new List<ServerEntry>();
    }
}
