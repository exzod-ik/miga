using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Windows;
using MIGA_Agent.Services;
using MIGA_Agent.ViewModels;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Startup += async (_, _) =>
        {
            var directory = Directory.CreateTempSubdirectory("miga-client-ui-test-");
            try
            {
                await CheckClientAsync(directory.FullName);
                Console.WriteLine("Client UI: draft validation, server activation, save/reopen, responsive service start and timeout passed");
                app.Shutdown();
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(error);
                app.Shutdown(1);
            }
            finally { directory.Delete(true); }
        };
        return app.Run();
    }

    private static async Task CheckClientAsync(string directory)
    {
        var config = new ClientConfigService(Path.Combine(directory, "config.json"));
        var local = new DelayedService();
        var dialogs = DispatchProxy.Create<IDialogService, TestDialogs>();
        var messages = (TestDialogs)(object)dialogs;
        var model = new MainViewModel(local, config, dialogs);
        await model.Initialization;

        model.AddServerCommand.Execute(null);
        var draft = model.SelectedServer!;
        draft.ConnectionName = "Draft";
        draft.RedirectProcesses.Add(new("demo.exe"));
        if (await model.ConfirmClosingAsync() || !model.HasUnsavedChanges || model.SelectedServer != draft ||
            !messages.Errors.Any(error => error.Contains("Draft")) || (await config.LoadAsync()).Servers.Count != 0)
            throw new Exception("saving an unconfigured draft did not preserve the edited tab");

        draft.ProfileId = "fake-profile";
        draft.ServerIp = "example.test";
        if (!await model.ConfirmClosingAsync() || model.HasUnsavedChanges)
            throw new Exception("configured tab did not save");
        var reopened = new MainViewModel(local, config, dialogs);
        await reopened.Initialization;
        if (reopened.Servers.Single().RedirectProcesses.Single().Value != "demo.exe")
            throw new Exception("rule was not recovered after reopening");

        var first = reopened.Servers.Single();
        reopened.AddServerCommand.Execute(null);
        var second = reopened.SelectedServer!;
        second.ConnectionName = first.ConnectionName;
        second.ProfileId = "second-profile";
        second.ServerIp = "second.test";
        second.RedirectProcesses.Add(new("demo.exe"));
        if (!first.RedirectProcesses.Single().IsConflicting || !second.RedirectProcesses.Single().IsConflicting ||
            !await reopened.ConfirmClosingAsync() || messages.ConflictConfirmations != 1)
            throw new Exception("same-name active tabs did not report their overlapping rules");
        second.Enabled = false;
        if (!reopened.HasUnsavedChanges || second.CanUseForFullRouting ||
            !second.TabTitle.EndsWith(" · отключён") ||
            first.RedirectProcesses.Single().IsConflicting || second.RedirectProcesses.Single().IsConflicting ||
            !await reopened.ConfirmClosingAsync() || messages.ConflictConfirmations != 1)
            throw new Exception("disabled tab did not update validation, title or dirty state");
        var restored = new MainViewModel(local, config, dialogs);
        await restored.Initialization;
        second = restored.Servers[1];
        if (second.Enabled || second.RedirectProcesses.Single().Value != "demo.exe" || restored.HasUnsavedChanges)
            throw new Exception("disabled tab and its rule were not restored");
        restored.RoutingMode = "full";
        restored.FullRoutingServer = second;
        if (await restored.ConfirmClosingAsync())
            throw new Exception("disabled tab was accepted for full routing");
        restored.FullRoutingServer = restored.Servers[0];
        if (!await restored.ConfirmClosingAsync())
            throw new Exception("active full routing profile did not save with a disabled tab");
        restored.RoutingMode = "split";
        restored.Servers[0].Enabled = false;
        if (!await restored.ConfirmClosingAsync() || (await config.LoadAsync()).Servers.Any(tab => tab.Enabled))
            throw new Exception("split routing did not save with all tabs disabled");
        second.Enabled = true;
        restored.Servers[0].Enabled = true;
        if (!second.RedirectProcesses.Single().IsConflicting)
            throw new Exception("reenabling tabs did not restore conflict warnings");

        var start = model.StartLocalServiceCommand.ExecuteAsync(null);
        await local.StartEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        if (start.IsCompleted || model.ServiceStatus != "Запускается…" ||
            model.StartLocalServiceCommand.CanExecute(null) || model.StopLocalServiceCommand.CanExecute(null) ||
            model.RefreshServiceStatusCommand.CanExecute(null))
            throw new Exception("start was not pending with service commands disabled");
        local.AllowStart.SetResult();
        await start;
        if (model.ServiceStatus != "Работает" || !model.StopLocalServiceCommand.CanExecute(null))
            throw new Exception("service state after delayed start was not refreshed");

        var stop = model.StopLocalServiceCommand.ExecuteAsync(null);
        await local.StopEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        if (stop.IsCompleted || model.ServiceStatus != "Останавливается…")
            throw new Exception("stop was not pending");
        local.AllowStop.SetResult();
        await stop;
        if (model.ServiceStatus != "Работает" || !model.StopLocalServiceCommand.CanExecute(null) ||
            !messages.Errors.Any(error => error.Contains("synthetic timeout")))
            throw new Exception("service state after timeout was not refreshed");
    }

    private sealed class DelayedService : ILocalServiceManager
    {
        public TaskCompletionSource StartEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource StopEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AllowStart { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AllowStop { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ServiceControllerStatus status = ServiceControllerStatus.Stopped;

        public ServiceControllerStatus? GetStatus() => status;
        public void ReloadConfig() => throw new NotSupportedException();

        public void Start()
        {
            StartEntered.SetResult();
            AllowStart.Task.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
            status = ServiceControllerStatus.Running;
        }

        public void Stop()
        {
            StopEntered.SetResult();
            AllowStop.Task.WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult();
            throw new System.TimeoutException("synthetic timeout");
        }
    }
}

public class TestDialogs : DispatchProxy
{
    public List<string> Errors { get; } = [];
    public int ConflictConfirmations { get; private set; }

    protected override object? Invoke(MethodInfo? method, object?[]? args)
    {
        switch (method!.Name)
        {
            case "ShowUnsavedChangesDialog": return UnsavedChangesDecision.Save;
            case "ShowYesNo": return true;
            case "ShowIssuesConfirmation":
                ConflictConfirmations++;
                return true;
            case "ShowInfo": return null;
            case "ShowError":
                Errors.Add((string)args![0]!);
                return null;
            default: throw new NotSupportedException(method.Name);
        }
    }
}
