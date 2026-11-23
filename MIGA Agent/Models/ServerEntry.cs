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
        [JsonPropertyName("protocol")]
        public int Protocol { get; set; } = 2;

        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;

        [JsonPropertyName("profile_id")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ProfileId { get; set; }

        [JsonPropertyName("requires_invitation")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public bool RequiresInvitation { get; set; }

        [JsonPropertyName("connection_name")]
        public string ConnectionName { get; set; } = string.Empty;

        [JsonPropertyName("server_ip")]
        public string ServerIp { get; set; } = string.Empty;

        [JsonPropertyName("control_ports")]
        public PortRange ControlPorts { get; set; } = new PortRange();

        [JsonPropertyName("redirect_processes")]
        public List<string> RedirectProcesses { get; set; } = new List<string>();

        [JsonPropertyName("redirect_ips")]
        public List<string> RedirectIps { get; set; } = new List<string>();

        [JsonPropertyName("redirect_domains")]
        public List<string> RedirectDomains { get; set; } = new List<string>();
    }
}
