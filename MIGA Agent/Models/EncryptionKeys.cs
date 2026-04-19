using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace MIGA_Agent.Models
{
    public class EncryptionKeys
    {
        [JsonPropertyName("xor_key")]
        public string XorKey { get; set; } = string.Empty;

        [JsonPropertyName("swap_key")]
        public string SwapKey { get; set; } = string.Empty;
    }
}
