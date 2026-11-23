using System.Diagnostics;
using MIGA_Agent.Services;

internal static class AdminAutosaveTests
{
    public static async Task RunAsync()
    {
        await CheckEditorLockAsync();
        List<IReadOnlyList<ManagedServerEntry>> writes = [];
        int clean = 0;
        var autosave = new AdminServerAutosave(entries => { writes.Add(entries); return Task.CompletedTask; }, () => clean++, error => throw error, TimeSpan.FromMilliseconds(30));
        autosave.Schedule([new("first", "first.example", "root")]);
        autosave.Schedule([new("latest", "latest.example", "user")]);
        await Task.Delay(100);
        if (writes.Count != 1 || writes[0][0].Name != "latest" || autosave.HasPending || clean != 1) throw new Exception("autosave debounce");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        writes.Clear(); clean = 0;
        autosave = new AdminServerAutosave(async entries => { writes.Add(entries); if (writes.Count == 1) { entered.SetResult(); await release.Task; } }, () => clean++, error => throw error, TimeSpan.FromHours(1));
        var mutable = new List<ManagedServerEntry> { new("snapshot", "a.example", "root") };
        autosave.Schedule(mutable);
        mutable.Clear();
        Task flush = autosave.FlushAsync();
        await entered.Task;
        autosave.Schedule([new("new revision", "b.example", "user")]);
        if (clean != 0 || !autosave.HasPending) throw new Exception("autosave cleared unsaved revision");
        release.SetResult();
        await flush;
        if (writes.Count != 2 || writes[0][0].Name != "snapshot" || writes[1][0].Name != "new revision" || clean != 1 || autosave.HasPending) throw new Exception("autosave snapshot serialization");
        bool fail = true;
        autosave = new AdminServerAutosave(_ => fail ? Task.FromException(new IOException("synthetic failure")) : Task.CompletedTask, () => clean++, _ => { }, TimeSpan.FromHours(1));
        autosave.Schedule([new("retry", "c.example", "user")]);
        try { await autosave.FlushAsync(); throw new Exception("autosave swallowed failure"); } catch (IOException) { }
        if (!autosave.HasPending) throw new Exception("autosave failure lost pending data");
        fail = false;
        await autosave.FlushAsync();
        if (autosave.HasPending) throw new Exception("autosave retry");
        Console.WriteLine("Admin autosave: debounce, immutable snapshot, serialized revisions, flush and error retry passed");
    }

    private static async Task CheckEditorLockAsync()
    {
        var folder = Directory.CreateTempSubdirectory("miga-admin-editor-test-");
        var path = Path.Combine(folder.FullName, "admin-servers.json");
        try
        {
            var first = new AdminConfigService(path);
            using (first.AcquireEditorLock())
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
                start.ArgumentList.Add("--admin-editor-lock");
                start.ArgumentList.Add(path);
                using var second = Process.Start(start) ?? throw new Exception("could not start a second editor");
                await second.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                if (second.ExitCode != 32) throw new Exception("another editor opened the same list");
                await first.SaveAsync([new("first", "first.example", "root")]);
            }

            var reopened = new AdminConfigService(path);
            using var editor = reopened.AcquireEditorLock();
            if ((await reopened.LoadAsync()).Single().Name != "first") throw new Exception("first editor lost its changes");
        }
        finally { folder.Delete(true); }
    }
}
