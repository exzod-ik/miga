using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    public class PortRange
    {
        [JsonPropertyName("start")]
        public int Start { get; set; } = 10000;

        [JsonPropertyName("end")]
        public int End { get; set; } = 15000;
    }
}
