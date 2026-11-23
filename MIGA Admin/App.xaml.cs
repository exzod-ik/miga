using System.IO;
using System.Windows;
using MIGA_Agent.Services;

namespace MIGA_Agent;

public partial class AdminApp : Application
{
    private FileStream? instanceLock;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try
        {
            instanceLock = new AdminConfigService().AcquireEditorLock();
        }
        catch (IOException error) when ((error.HResult & 0xffff) == 32)
        {
            MessageBox.Show("MIGA Admin уже открыт для этой учётной записи.", "MIGA Admin", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(error.Message, "MIGA Admin — ошибка блокировки списка VPS", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }
        var notifications = new NotificationCenter();
        new AdminWindow(new DialogService(notifications), notifications).Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        base.OnExit(e);
        instanceLock?.Dispose();
    }
}
