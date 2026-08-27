using System.Text.Encodings.Web;
using System.Text.Json;

namespace MIGA_Agent.Helpers
{
    /// <summary>
    /// Общие настройки сериализации JSON.
    /// </summary>
    public static class JsonOptions
    {
        public static JsonSerializerOptions Default { get; } = new()
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
    }
}

