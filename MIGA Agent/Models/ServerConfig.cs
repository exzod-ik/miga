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

        [JsonPropertyName("dns_server")]
        public string DnsServer { get; set; } = "8.8.8.8";
    }
}
