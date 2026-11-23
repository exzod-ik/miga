using System.Security.Cryptography;

namespace MIGA_Agent.Services;

public static class DiagnosticAuthorization
{
    public static bool MatchesCertificate(byte[] certificate, string fingerprint)
    {
        try
        {
            var encoded = fingerprint.Replace('-', '+').Replace('_', '/');
            encoded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
            var expected = Convert.FromBase64String(encoded);
            return expected.Length == 32 && CryptographicOperations.FixedTimeEquals(SHA256.HashData(certificate), expected);
        }
        catch (FormatException) { return false; }
    }
}
