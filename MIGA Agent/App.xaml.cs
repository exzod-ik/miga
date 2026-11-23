using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Windows;
using MIGA_Agent.Services;
using MIGA_Agent.ViewModels;
using MIGA_Agent.Views;

namespace MIGA_Agent
{
    public partial class App : Application
    {
        private static IHost? _host;
        private Mutex? instance;
        private bool ownsInstance;

        public static IServiceProvider Services => _host?.Services ?? throw new InvalidOperationException("Host is not built.");

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            try
            {
                instance = new Mutex(false, @"Global\MIGA.Client.Gui.v2");
                try { ownsInstance = instance.WaitOne(0); } catch (AbandonedMutexException) { ownsInstance = true; }
            }
            catch (UnauthorizedAccessException) { ownsInstance = false; }
            if (!ownsInstance)
            {
                MessageBox.Show("MIGA Client уже открыт. Закройте текущее окно и повторите открытие приглашения из MIGA Admin.", "MIGA Client", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }

            _host = CreateHostBuilder().Build();
            await _host.StartAsync();

            var mainWindow = Services.GetRequiredService<MainWindow>();
            mainWindow.Show();
            if (e.Args.Length == 2 && e.Args[0] == "--invitation-pipe")
            {
                try
                {
                    string value = await InvitationHandoff.ReceiveAsync(e.Args[1]);
                    var viewModel = Services.GetRequiredService<MainViewModel>();
                    await viewModel.Initialization;
                    await viewModel.AddInvitationAsync(value);
                }
                catch { Services.GetRequiredService<IDialogService>().ShowError("Не удалось получить приглашение из MIGA Admin."); }
            }
        }

        private static IHostBuilder CreateHostBuilder()
        {
            return Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    // Регистрация сервисов
                    services.AddSingleton<ILocalServiceManager, LocalServiceManager>();
                    services.AddSingleton<IClientConfigService, ClientConfigService>();

                    services.AddSingleton<NotificationCenter>();
                    services.AddSingleton<IDialogService, DialogService>();

                    // Регистрация ViewModel и окон
                    services.AddSingleton<MainViewModel>();
                    services.AddSingleton<MainWindow>();
                });
        }

        protected override async void OnExit(ExitEventArgs e)
        {
            if (_host != null)
            {
                await _host.StopAsync();
                _host.Dispose();
            }
            if (ownsInstance) instance?.ReleaseMutex();
            instance?.Dispose();
            base.OnExit(e);
        }
    }
}