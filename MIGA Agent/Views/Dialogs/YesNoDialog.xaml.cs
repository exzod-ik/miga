using System.Windows;

namespace MIGA_Agent.Views.Dialogs
{
    public partial class YesNoDialog : Window
    {
        public bool? Result { get; private set; } = false;

        public YesNoDialog(string message, string title = "Подтверждение")
        {
            InitializeComponent();
            Title = title;
            MessageTextBlock.Text = message;
            Owner = Application.Current.MainWindow;
        }

        private void YesButton_Click(object sender, RoutedEventArgs e)
        {
            Result = true;
            Close();
        }

        private void NoButton_Click(object sender, RoutedEventArgs e)
        {
            Result = false;
            Close();
        }
    }
}