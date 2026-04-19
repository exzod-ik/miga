using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Windows;
using MIGA_Agent.Services;
using MIGA_Agent.ViewModels;
using MIGA_Agent.Views;
using Notification.Wpf;

namespace MIGA_Agent
{
    public partial class App : Application
    {
        private static IHost? _host;

        public static IServiceProvider Services => _host?.Services ?? throw new InvalidOperationException("Host is not built.");

        // Синглтон NotificationManager для использования во всём приложении
        public static NotificationManager NotificationManager { get; } = new NotificationManager();

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            _host = CreateHostBuilder().Build();
            await _host.StartAsync();

            var mainWindow = Services.GetRequiredService<MainWindow>();
            mainWindow.Show();
        }

        private static IHostBuilder CreateHostBuilder()
        {
            return Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    // Регистрация сервисов
                    services.AddSingleton<ILocalServiceManager, LocalServiceManager>();
                    services.AddSingleton<IClientConfigService, ClientConfigService>();
                    services.AddSingleton<ISshManager, SshManager>();

                    // Регистрация NotificationManager как синглтона
                    services.AddSingleton(NotificationManager);

                    // Регистрация DialogService (он получит NotificationManager через конструктор)
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
            base.OnExit(e);
        }
    }
}