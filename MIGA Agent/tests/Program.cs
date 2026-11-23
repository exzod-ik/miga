using System.Text;
using MIGA_Agent.Models;
using MIGA_Agent.Services;
string B(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+','-').Replace('/','_');
string Wrap(string json) => "miga2:" + B(Encoding.UTF8.GetBytes(json));
string key = B(new byte[32]), id = B(new byte[16]);
string json = "{\"v\":2,\"host\":\"vpn.example.com\",\"ports\":[10000,15000],\"server_key\":\"" + key + "\",\"server_secret\":\"" + key + "\",\"client_id\":\"" + id + "\",\"client_secret\":\"" + key + "\"}";
if (args.Length == 2 && args[0] == "--admin-editor-lock")
{
    try { using var editor = new AdminConfigService(args[1]).AcquireEditorLock(); }
    catch (IOException error) when ((error.HResult & 0xffff) == 32) { Environment.ExitCode = 32; }
    return;
}
if (args.Length == 2 && args[0] == "--invitation-pipe")
{
    string received = await MIGA_Agent.Services.InvitationHandoff.ReceiveAsync(args[1]);
    if (received != Wrap(json)) throw new Exception("handoff payload changed");
    await File.WriteAllTextAsync(Path.Combine(AppContext.BaseDirectory, "handoff.ok"), "ok");
    return;
}
if (args.Length == 1 && args[0] == "--handoff-test-admin")
{
    await MIGA_Agent.Services.InvitationHandoff.SendAsync(Wrap(json), startInfo =>
    {
        if (!startInfo.UseShellExecute || startInfo.Verb != "runas" || startInfo.ArgumentList.Count != 2 ||
            startInfo.ArgumentList[0] != "--invitation-pipe" || !Guid.TryParseExact(startInfo.ArgumentList[1], "N", out _) ||
            startInfo.Arguments.Length != 0)
            throw new Exception("Expected only a pipe identifier in the elevated launch arguments.");
        startInfo.UseShellExecute = false;
        startInfo.Verb = "";
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardError = true;
        var child = System.Diagnostics.Process.Start(startInfo);
        if (child != null)
        {
            child.ErrorDataReceived += (_, e) => { if (e.Data != null) Console.Error.WriteLine(e.Data); };
            child.BeginErrorReadLine();
        }
        return child;
    });
    return;
}
var parsed = ProtocolV2Invitation.Parse(Wrap(json));
if (parsed.Host != "vpn.example.com" || parsed.FirstPort != 10000 || parsed.LastPort != 15000) throw new Exception("valid");
int cases = 0;
void Reject(string invitation) { try { ProtocolV2Invitation.Parse(invitation); } catch (InvalidDataException) { cases++; return; } throw new Exception("accepted invalid"); }
Reject(Wrap(json.Replace("\"v\":2", "\"v\":2,\"v\":2")));
Reject(Wrap(json.Replace("\"v\":2", "\"v\":1")));
Reject(Wrap(json.Replace("[10000,15000]", "[15000,10000]")));
Reject(Wrap(json.Replace("[10000,15000]", "[0,65536]")));
Reject(Wrap(json.Replace("vpn.example.com", "::1")));
Reject(Wrap(json.Replace(id, "AA")));
Reject(Wrap(json.Replace("\"host\":", "\"unknown\":")));
Reject(Wrap(json) + "=");
Reject("miga2:" + new string('a',4096));
Console.WriteLine($"Agent invitation: valid hostname + {cases} rejection cases passed");

await ConfigMigrationTests.RunAsync();

var certificateBytes = Encoding.UTF8.GetBytes("test certificate");
var fingerprint = B(System.Security.Cryptography.SHA256.HashData(certificateBytes));
if (!MIGA_Agent.Services.DiagnosticAuthorization.MatchesCertificate(certificateBytes, fingerprint) ||
    MIGA_Agent.Services.DiagnosticAuthorization.MatchesCertificate(Encoding.UTF8.GetBytes("another certificate"), fingerprint) ||
    MIGA_Agent.Services.DiagnosticAuthorization.MatchesCertificate(certificateBytes, "invalid!") ||
    MIGA_Agent.Services.DiagnosticAuthorization.MatchesCertificate(certificateBytes, "AA"))
    throw new Exception("diagnostic certificate pin verification");
Console.WriteLine("Diagnostic certificate pin: matching, substitution, malformed and short fingerprint cases passed");

using (var generator = new QRCoder.QRCodeGenerator())
using (var data = generator.CreateQrCode(Wrap(json), QRCoder.QRCodeGenerator.ECCLevel.M))
using (var qr = new QRCoder.PngByteQRCode(data))
{
    var png = qr.GetGraphic(6);
    if (png.Length < 100 || !png.Take(8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }))
        throw new Exception("invitation QR PNG generation");
}
Console.WriteLine("Invitation QR: synthetic miga2 payload generates PNG successfully");

await AdminAutosaveTests.RunAsync();

await SplitTests.RunAsync(Wrap(json));
