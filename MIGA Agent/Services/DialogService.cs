using MIGA_Agent.Services;
using MIGA_Agent.Views.Dialogs;
using Ookii.Dialogs.Wpf;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace MIGA_Agent.Services
{
    public class DialogService : IDialogService
    {
        private readonly NotificationCenter _notificationCenter;

        public DialogService(NotificationCenter notificationCenter)
        {
            _notificationCenter = notificationCenter;
        }

        private void ShowNotification(string message, string title, NotificationKind kind)
        {
            _notificationCenter.Show(title, message, kind);
        }

        public void ShowInfo(string message, string title = "Информация")
        {
            ShowNotification(message, title, NotificationKind.Information);
        }

        public void ShowWarning(string message, string title = "Предупреждение")
        {
            ShowNotification(message, title, NotificationKind.Warning);
        }

        public void ShowError(string message, string title = "Ошибка")
        {
            ShowNotification(message, title, NotificationKind.Error);
        }

        public bool ShowYesNo(string message, string title = "Подтверждение")
        {
            var dialog = new YesNoDialog(message, title);
            dialog.ShowDialog();
            return dialog.Result == true;
        }

        public UnsavedChangesDecision ShowUnsavedChangesDialog(string message, string title = "Несохранённые изменения")
        {
            var dialog = new UnsavedChangesDialog(message, title);
            dialog.ShowDialog();
            return dialog.Decision;
        }

        public bool ShowIssuesConfirmation(string title, string message, IEnumerable<string> issues)
        {
            var dialog = new IssuesDialog(title, message, issues);
            dialog.ShowDialog();
            return dialog.DialogResult == true;
        }

        public NotificationEntry ShowPersistent(string title)
        {
            return _notificationCenter.ShowProgress(title);
        }

        public void UpdatePersistent(NotificationEntry notification, string title, string message)
        {
            _notificationCenter.UpdateProgress(notification, title, message);
        }

        public void ClosePersistent(NotificationEntry notification, string title, string message, bool isError = false)
        {
            _notificationCenter.CompleteProgress(notification, title, message, isError);
        }

        public string? ShowFolderDialog(string description = "Выберите папку", string? selectedPath = null)
        {
            var dialog = new VistaFolderBrowserDialog
            {
                Description = description,
                UseDescriptionForTitle = true,
                SelectedPath = selectedPath ?? Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            if (dialog.ShowDialog() == true)
                return dialog.SelectedPath;

            return null;
        }

        public string? ShowInputDialog(string prompt, string title = "Ввод", string defaultValue = "")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 440,
                SizeToContent = SizeToContent.Height,
                ShowInTaskbar = false,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.MainWindow,
                ResizeMode = ResizeMode.NoResize
            };

            var grid = new System.Windows.Controls.Grid();
            grid.Margin = new Thickness(10);
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });

            var promptText = new System.Windows.Controls.TextBlock
            {
                Text = prompt,
                TextWrapping = System.Windows.TextWrapping.Wrap
            };
            var promptView = new System.Windows.Controls.ScrollViewer
            {
                Content = promptText,
                MaxHeight = 180,
                VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 0, 0, 10)
            };

            var inputBox = new System.Windows.Controls.TextBox
            {
                Text = defaultValue,
                Margin = new Thickness(0, 0, 0, 10)
            };
            System.Windows.Controls.Grid.SetRow(inputBox, 1);

            var buttonPanel = new System.Windows.Controls.StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Right
            };
            var okButton = new System.Windows.Controls.Button { Content = "OK", MinWidth = 75, Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 10, 0) };
            var cancelButton = new System.Windows.Controls.Button { Content = "Отмена", MinWidth = 75, Padding = new Thickness(10, 5, 10, 5) };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            System.Windows.Controls.Grid.SetRow(buttonPanel, 2);

            grid.Children.Add(promptView);
            grid.Children.Add(inputBox);
            grid.Children.Add(buttonPanel);

            dialog.Content = grid;

            string? result = null;

            inputBox.Focus();

            inputBox.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter)
                {
                    result = inputBox.Text;
                    dialog.Close();
                }
            };

            okButton.Click += (s, e) => { result = inputBox.Text; dialog.Close(); };
            cancelButton.Click += (s, e) => dialog.Close();

            dialog.ShowDialog();
            return result;
        }

        public string? ShowMultiLineInputDialog(string prompt, string title, string defaultValue = "")
        {
            var dialog = new Window
            {
                Title = title,
                Width = 500,
                Height = 355,
                MinWidth = 400,
                MinHeight = 290,
                ShowInTaskbar = false,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.MainWindow,
                ResizeMode = ResizeMode.CanResize
            };

            var grid = new System.Windows.Controls.Grid();
            grid.Margin = new Thickness(10);
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = new System.Windows.GridLength(1, System.Windows.GridUnitType.Star) });
            grid.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });

            var promptText = new System.Windows.Controls.TextBlock
            {
                Text = prompt,
                TextWrapping = System.Windows.TextWrapping.Wrap
            };
            var promptView = new System.Windows.Controls.ScrollViewer
            {
                Content = promptText,
                MaxHeight = 105,
                VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 0, 0, 10)
            };

            var inputBox = new System.Windows.Controls.TextBox
            {
                Text = defaultValue,
                AcceptsReturn = true,
                AcceptsTab = false,
                TextWrapping = System.Windows.TextWrapping.Wrap,
                VerticalScrollBarVisibility = System.Windows.Controls.ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 0, 0, 10)
            };
            System.Windows.Controls.Grid.SetRow(inputBox, 1);

            var buttonPanel = new System.Windows.Controls.StackPanel
            {
                Orientation = System.Windows.Controls.Orientation.Horizontal,
                HorizontalAlignment = System.Windows.HorizontalAlignment.Right
            };
            var okButton = new System.Windows.Controls.Button { Content = "OK", MinWidth = 75, Padding = new Thickness(10, 5, 10, 5), Margin = new Thickness(0, 0, 10, 0), IsDefault = true };
            var cancelButton = new System.Windows.Controls.Button { Content = "Отмена", MinWidth = 75, Padding = new Thickness(10, 5, 10, 5), IsCancel = true };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            System.Windows.Controls.Grid.SetRow(buttonPanel, 2);

            grid.Children.Add(promptView);
            grid.Children.Add(inputBox);
            grid.Children.Add(buttonPanel);

            dialog.Content = grid;

            string? result = null;
            inputBox.Focus();

            okButton.Click += (s, e) => { result = inputBox.Text; dialog.Close(); };
            cancelButton.Click += (s, e) => dialog.Close();

            dialog.ShowDialog();
            return result;
        }
    }
}