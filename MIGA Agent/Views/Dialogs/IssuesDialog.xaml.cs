using System.Collections.Generic;
using System.Windows;

namespace MIGA_Agent.Views.Dialogs
{
    public partial class IssuesDialog : Window
    {
        public IssuesDialog(string title, string message, IEnumerable<string> issues)
        {
            InitializeComponent();
            Title = title;
            MessageTextBlock.Text = message;
            foreach (var issue in issues)
                IssuesList.Items.Add(issue);
        }

        private void ApplyButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
