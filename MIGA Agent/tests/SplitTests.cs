using System.Diagnostics;
using System.IO;
using System.Text.Json;
using MIGA_Agent.Services;

public static class SplitTests
{
    public static async Task RunAsync(string syntheticInvitation)
    {
        string root = Path.Combine(AppContext.BaseDirectory, "split-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string legacy = Path.Combine(root, "legacy.json"), config = Path.Combine(root, "admin.json");
            string legacyJson = "{\"protocol\":2,\"servers\":[{\"server_ip\":\"vpn.example.com\",\"connection_name\":\"VPS\",\"server_ssh_user\":\"operator\",\"server_ssh_password\":\"DO-NOT-PERSIST\",\"profile_id\":\"profile\",\"redirect_processes\":[\"browser.exe\"]}]}";
            await File.WriteAllTextAsync(legacy, legacyJson);
            var service = new AdminConfigService(config);
            var entries = await service.LoadAsync(legacy);
            if (entries.Count != 1 || entries[0] != new ManagedServerEntry("VPS", "vpn.example.com", "operator")) throw new Exception("admin migration");
            if (await File.ReadAllTextAsync(legacy) != legacyJson) throw new Exception("legacy modified");
            string saved = await File.ReadAllTextAsync(config);
            if (saved.Contains("DO-NOT-PERSIST") || saved.Contains("profile_id") || saved.Contains("browser.exe")) throw new Exception("client secrets/rules persisted in admin");
            await File.WriteAllTextAsync(legacy, "malformed");
            if ((await service.LoadAsync(legacy)).Count != 1) throw new Exception("migration repeated");
            await service.SaveAsync([]);
            if ((await service.LoadAsync(legacy)).Count != 0) throw new Exception("empty list not preserved");
            await File.WriteAllTextAsync(config, "[null]");
            try { await service.LoadAsync(); throw new Exception("null accepted"); } catch (InvalidDataException) { }
            if (await File.ReadAllTextAsync(config) != "[null]") throw new Exception("corrupt admin overwritten");
            Console.WriteLine("Admin migration: independent list, one-time import, no password/profile/rules, corrupt preservation passed");

            using var generator = new QRCoder.QRCodeGenerator();
            using var data = generator.CreateQrCode(syntheticInvitation, QRCoder.QRCodeGenerator.ECCLevel.M);
            using var qr = new QRCoder.PngByteQRCode(data);
            string image = Path.Combine(root, "invitation.png");
            await File.WriteAllBytesAsync(image, qr.GetGraphic(6));
            if (InvitationQrReader.Read(image) != syntheticInvitation) throw new Exception("QR roundtrip");
            Console.WriteLine("QR image: full synthetic invitation encode/decode roundtrip passed");

            foreach (string invalid in new[] { "", "../escape", new string('a', 33), "00000000-0000-0000-0000-000000000000" })
            {
                try { await InvitationHandoff.ReceiveAsync(invalid); throw new Exception("invalid pipe accepted"); }
                catch (InvalidDataException) { }
            }
            try { await InvitationHandoff.SendAsync("secret-not-invitation"); throw new Exception("invalid payload accepted"); }
            catch (InvalidDataException) { }
            using (var self = Process.GetCurrentProcess())
            {
                InvitationHandoff.VerifyPeer((uint)self.Id, self.MainModule!.FileName);
                try { InvitationHandoff.VerifyPeer((uint)self.Id, Path.Combine(root, "wrong.exe")); throw new Exception("wrong peer path accepted"); }
                catch (IOException) { }
            }
            string output = AppContext.BaseDirectory;
            string apphost = Environment.ProcessPath!;
            foreach (string name in new[] { "MIGA Client.exe", "MIGA Admin.exe" })
                File.Copy(apphost, Path.Combine(output, name), true);
            string marker = Path.Combine(output, "handoff.ok");
            if (File.Exists(marker)) File.Delete(marker);
            try
            {
                await InvitationHandoff.SendAsync(syntheticInvitation, _ => throw new System.ComponentModel.Win32Exception(1223));
                throw new Exception("cancelled elevation was accepted");
            }
            catch (IOException error) when (error.InnerException is System.ComponentModel.Win32Exception { NativeErrorCode: 1223 }) { }
            using var admin = Process.Start(new ProcessStartInfo(Path.Combine(output, "MIGA Admin.exe"), "--handoff-test-admin")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true
            })!;
            var errors = admin.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(55));
            await admin.WaitForExitAsync(timeout.Token);
            if (admin.ExitCode != 0) throw new Exception($"handoff sender failed: {admin.ExitCode}{Environment.NewLine}{await errors}");
            while (!File.Exists(marker)) await Task.Delay(30, timeout.Token);
            if (admin.ExitCode != 0 || await File.ReadAllTextAsync(marker) != "ok") throw new Exception("handoff process integration");
            File.Delete(marker);
            Console.WriteLine("Invitation handoff: bounded input rejection and real same-user/session named pipe between isolated process aliases passed");
        }
        finally { Directory.Delete(root, true); }
    }
}
