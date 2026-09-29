using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
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

        private void ShareServer_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button { ContextMenu: { } menu } button)
            {
                menu.PlacementTarget = button;
                menu.IsOpen = true;
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

                if (await vm.ConfirmClosingAsync())
                {
                    _forceClose = true;
                    Close();
                }
            }
        }
    }
}
