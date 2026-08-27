using System.ComponentModel;
using System.Windows;
using MIGA_Agent.ViewModels;

namespace MIGA_Agent.Views
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private bool _forceClose;

        public MainWindow(MainViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel; // Устанавливаем контекст данных
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
