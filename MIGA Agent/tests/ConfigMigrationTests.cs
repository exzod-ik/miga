using System.Text.Json;
using MIGA_Agent.Services;

internal static class ConfigMigrationTests
{
    public static async Task RunAsync()
    {
        const string server = """{"server_ip":"192.0.2.1","connection_name":"Первый","server_ports":{"start":10000,"end":15000},"encryption":{"xor_key":"obsolete-secret","swap_key":"obsolete-secret"},"redirect_processes":["App.EXE","other.exe"],"redirect_ips":["203.0.113.1","203.0.113.20-203.0.113.30"],"redirect_domains":["*.example.com","example.org"]}""";
        string legacy = "{\"log_level\":\"warning\",\"tunnel_max_mss\":1380,\"servers\":[" + server + "," + server.Replace("Первый", "Второй") + "]}";
        var directory = Path.Combine(Path.GetTempPath(), "miga-migration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "config.json");
        var service = new ClientConfigService(path);
        int rejected = 0;
        try
        {
            Check((await service.LoadAsync()).DnsResolverEnabled, "new configuration enables resolver");
            await File.WriteAllTextAsync(path, """{"protocol":2,"servers":[]}""");
            Check((await service.LoadAsync()).DnsResolverEnabled, "v2 configuration with missing option enables resolver");
            await File.WriteAllTextAsync(path, """{"protocol":2,"dns_resolver_enabled":false,"servers":[]}""");
            Check(!(await service.LoadAsync()).DnsResolverEnabled, "v2 configuration preserves explicit false");
            await File.WriteAllTextAsync(path, legacy.Replace("1380", """1380,"dns_resolver_enabled":false"""));
            Check(!(await service.LoadAsync()).DnsResolverEnabled, "legacy migration preserves explicit false");
            Check(!(await service.LoadAsync()).DnsResolverEnabled, "explicit false survives reloading migrated configuration");
            await File.WriteAllTextAsync(path, legacy);
            var config = await service.LoadAsync();
            Check(config.Protocol == 2 && config.LogLevel == "warning" && config.TunnelMaxMss == 1380, "global settings");
            Check(config.Servers.Count == 2 && config.Servers[1].ConnectionName == "Второй", "ordered servers");
            foreach (var entry in config.Servers)
            {
                Check(entry.Enabled && entry.RequiresInvitation && entry.ProfileId == null, "enabled pending invitation");
                Check(entry.RedirectProcesses.SequenceEqual(new[] { "App.EXE", "other.exe" }), "process rules");
                Check(entry.RedirectIps.SequenceEqual(new[] { "203.0.113.1", "203.0.113.20-203.0.113.30" }), "IP rules");
                Check(entry.RedirectDomains.SequenceEqual(new[] { "*.example.com", "example.org" }), "domain rules");
            }
            foreach (string rule in new[] { "0.0.0.0", "255.255.255.255", "203.0.113.1-203.0.113.20" })
                Check(ClientConfigCodec.IsValidIpRule(rule), "valid IPv4 rule");
            string originalIp = config.Servers[0].RedirectIps[0];
            foreach (string rule in new[] { "not-an-ip", "1.2.3", "127.1", "1.2.3.256", "01.2.3.4", "1.2.3.4-1.2.3.3", "1.2.3.4-", "::1", "1.2.3.4 -1.2.3.5" })
            {
                Check(!ClientConfigCodec.IsValidIpRule(rule), "invalid IPv4 rule");
                string beforeInvalidSave = await File.ReadAllTextAsync(path);
                config.Servers[0].RedirectIps[0] = rule;
                bool invalidIpRejected = false;
                try { await service.SaveAsync(config); }
                catch (InvalidDataException) { invalidIpRejected = true; }
                Check(invalidIpRejected && await File.ReadAllTextAsync(path) == beforeInvalidSave, "invalid IPv4 does not overwrite config");
            }
            config.Servers[0].RedirectIps[0] = originalIp;
            var saved = await File.ReadAllTextAsync(path);
            Check(!saved.Contains("obsolete-secret") && !saved.Contains("encryption") && !saved.Contains("server_ports"), "legacy credentials removed");
            await service.LoadAsync();
            Check(await File.ReadAllTextAsync(path) == saved, "load is idempotent");
            config.Servers[0].RequiresInvitation = false;
            config.Servers[0].ProfileId = "new-profile";
            await service.SaveAsync(config);
            var partial = await service.LoadAsync();
            Check(partial.Servers[0].ProfileId == "new-profile" && partial.Servers[1].RequiresInvitation, "partial invitation import preserves other server");
            Check(partial.Servers[0].RedirectProcesses.SequenceEqual(config.Servers[0].RedirectProcesses), "invitation keeps rules");
            Check(partial.DnsResolverEnabled, "legacy configuration with missing option enables resolver");
            Check(partial.RoutingMode == "split" && partial.FullRoutingProfileId == "", "legacy configuration defaults to split");
            config.Servers[1].RequiresInvitation = false;
            config.Servers[1].ProfileId = "second-profile";
            config.DnsResolverEnabled = true;
            config.RoutingMode = "full";
            config.FullRoutingProfileId = "second-profile";
            config.Servers.Reverse();
            await service.SaveAsync(config);
            var full = await service.LoadAsync();
            Check(full.DnsResolverEnabled, "resolver selection survives save and reload");
            Check(full.RoutingMode == "full" && full.FullRoutingProfileId == "second-profile" &&
                full.Servers[0].ProfileId == full.FullRoutingProfileId &&
                full.Servers[1].RedirectProcesses.SequenceEqual(partial.Servers[0].RedirectProcesses),
                "full mode and stable profile selection round-trip without deleting split rules");
            config.Servers.RemoveAt(0);
            bool missingFullProfileRejected = false;
            try { await service.SaveAsync(config); }
            catch (InvalidDataException) { missingFullProfileRejected = true; }
            Check(missingFullProfileRejected && (await service.LoadAsync()).Servers.Count == 2,
                "removing the selected profile requires choosing another server");
            full.Servers[0].Enabled = false;
            bool disabledFullProfileRejected = false;
            try { await service.SaveAsync(full); }
            catch (InvalidDataException) { disabledFullProfileRejected = true; }
            Check(disabledFullProfileRejected && (await service.LoadAsync()).Servers[0].Enabled,
                "disabled full-routing profile requires choosing another server");
            full.Servers[0].RequiresInvitation = true;
            full.Servers[0].ProfileId = null;
            full.FullRoutingProfileId = "new-profile";
            await service.SaveAsync(full);
            var enabledFull = await service.LoadAsync();
            Check(!enabledFull.Servers[0].Enabled && enabledFull.Servers[0].RequiresInvitation &&
                enabledFull.Servers[0].RedirectDomains.SequenceEqual(full.Servers[0].RedirectDomains) &&
                enabledFull.Servers[1].Enabled && enabledFull.FullRoutingProfileId == "new-profile",
                "disabled pending entry survives save and does not block an active full-routing profile");
            foreach (string input in new[] { server, server.Replace("{\"server_ip\"", "{\"protocol\":1,\"server_ip\"") })
            {
                var single = ClientConfigCodec.Decode(input, out bool migrated);
                Check(migrated && single.Servers.Count == 1 && single.Servers[0].RequiresInvitation, "single server migration");
            }
            foreach (string invalid in new[] {
                "{}", "{", legacy.Replace("\"log_level\"", "\"protocol\":3,\"log_level\""),
                legacy.Replace("\"log_level\"", "\"protocol\":\"1\",\"log_level\""),
                legacy.Replace("1380", "1380,\"dns_resolver_enabled\":\"true\""),
                legacy.Replace("1380", "null"), legacy.Replace("1380", "0"),
                legacy.Replace("\"warning\"", "\"unknown\""),
                legacy.Replace("[\"App.EXE\",\"other.exe\"]", "null"),
                legacy.Replace("[\"App.EXE\",\"other.exe\"]", "[42]"),
                legacy.Replace("\"server_ip\":", "\"server_ip\":\"duplicate\",\"server_ip\":"),
                saved.Replace("203.0.113.1", "999.0.113.1"),
                saved.Replace("\"enabled\": true", "\"enabled\": \"false\""),
                saved.Replace("\"requires_invitation\": true", "\"requires_invitation\": \"yes\""),
                saved.Replace("\"requires_invitation\": true", "\"requires_invitation\": true,\"profile_id\":\"unexpected\""),
                saved.Replace("\"requires_invitation\": true", "\"requires_invitation\": false") })
            {
                await File.WriteAllTextAsync(path, invalid);
                bool failed = false;
                try { await service.LoadAsync(); }
                catch (Exception e) when (e is InvalidDataException or JsonException) { failed = true; }
                Check(failed && await File.ReadAllTextAsync(path) == invalid, "invalid configuration must remain untouched");
                rejected++;
            }
            await File.WriteAllTextAsync(path, legacy);
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                bool failed = false;
                try { await service.LoadAsync(); } catch (IOException) { failed = true; }
                Check(failed, "locked destination must fail safely");
            }
            Check(await File.ReadAllTextAsync(path) == legacy && Directory.GetFiles(directory).Length == 1, "failed replacement preserves original and cleans temporary file");
            Console.WriteLine($"Windows migration: rules, invitation states, atomic persistence and {rejected} rejection cases passed");
        }
        finally { Directory.Delete(directory, true); }
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
