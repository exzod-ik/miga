using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using MIGA_Agent.ViewModels;
using MIGA_Agent.Services;

namespace MIGA_Agent.Views
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private bool _forceClose;
        private readonly NotificationCenter _notificationCenter;

        public MainWindow(MainViewModel viewModel, NotificationCenter notificationCenter)
        {
            InitializeComponent();
            _notificationCenter = notificationCenter;
            NotificationList.ItemsSource = notificationCenter.Items;
            DataContext = viewModel; // Устанавливаем контекст данных
        }



        private void ServerTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is not TabControl tabs || e.OriginalSource != tabs) return;
            _ = Dispatcher.InvokeAsync(() =>
            {
                if (tabs.SelectedItem is { } item && tabs.ItemContainerGenerator.ContainerFromItem(item) is TabItem tab)
                    tab.BringIntoView();
            }, System.Windows.Threading.DispatcherPriority.Loaded);
        }

        private void ProjectLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            e.Handled = true;
            try
            {
                Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true })?.Dispose();
            }
            catch (Win32Exception)
            {
                _notificationCenter.Show("GitHub", "Не удалось открыть ссылку в браузере.", NotificationKind.Error);
            }
        }

        private void DismissNotification_Click(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement { DataContext: NotificationEntry entry })
                _notificationCenter.Dismiss(entry);
        }

        protected override async void OnClosing(CancelEventArgs e)
        {
            base.OnClosing(e);

            if (_forceClose)
                return;

            // При наличии несохранённых изменений спрашиваем пользователя
            if (DataContext is MainViewModel vm && vm.HasUnsavedChanges)
            {
                e.Cancel = true;

                try
                {
                    if (await vm.ConfirmClosingAsync())
                    {
                        _forceClose = true;
                        _ = Dispatcher.BeginInvoke(new System.Action(Close));
                    }
                }
                catch (Exception error)
                {
                    _notificationCenter.Show("Ошибка сохранения", $"Не удалось сохранить конфигурацию: {error.Message}", NotificationKind.Error);
                }
            }
        }
    }
}
