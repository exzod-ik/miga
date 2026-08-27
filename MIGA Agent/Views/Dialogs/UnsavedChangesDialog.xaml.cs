using System.Windows;

namespace MIGA_Agent.Views.Dialogs
{
    public partial class UnsavedChangesDialog : Window
    {
        /// <summary>Результат выбора пользователя.</summary>
        public Services.UnsavedChangesDecision Decision { get; private set; } =
            Services.UnsavedChangesDecision.Cancel;

        public UnsavedChangesDialog(string message, string title)
        {
            InitializeComponent();
            Title = title;
            MessageTextBlock.Text = message;
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            Decision = Services.UnsavedChangesDecision.Save;
            Close();
        }

        private void DiscardButton_Click(object sender, RoutedEventArgs e)
        {
            Decision = Services.UnsavedChangesDecision.Discard;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Decision = Services.UnsavedChangesDecision.Cancel;
            Close();
        }
    }
}
