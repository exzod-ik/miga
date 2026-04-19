using MIGA_Agent.Services;
using MIGA_Agent.Views.Dialogs;
using Notification.Wpf;
using Notification.Wpf.Classes;
using Ookii.Dialogs.Wpf;
using System.Windows;
using System.Windows.Input;

namespace MIGA_Agent.Services
{
    using ProgressInfo = NotifierProgress<(double? value, string message, string title, bool? showCancel)>;

    public class DialogService : IDialogService
    {
        private readonly NotificationManager _notificationManager;
        private const string AreaName = "NotificationArea";

        public DialogService(NotificationManager notificationManager)
        {
            _notificationManager = notificationManager;
        }

        private void ShowNotification(string message, string title, NotificationType type)
        {
            _notificationManager.Show(new NotificationContent
            {
                Title = title,
                Message = message,
                Type = type
            },
            areaName: AreaName);
        }

        public void ShowInfo(string message, string title = "Информация")
        {
            ShowNotification(message, title, NotificationType.Information);
        }

        public void ShowWarning(string message, string title = "Предупреждение")
        {
            ShowNotification(message, title, NotificationType.Warning);
        }

        public void ShowError(string message, string title = "Ошибка")
        {
            ShowNotification(message, title, NotificationType.Error);
        }

        public bool ShowYesNo(string message, string title = "Подтверждение")
        {
            var dialog = new YesNoDialog(message, title);
            dialog.ShowDialog();
            return dialog.Result == true;
        }

        public ProgressInfo ShowPersistent(string title)
        {
            return _notificationManager.ShowProgressBar(Title: title, ShowCancelButton: false, ShowProgress: false, areaName: AreaName);
        }

        public void UpdatePersistent(ProgressInfo notification, string title, string message)
        {
            notification.Report((0, message, title, false));
        }

        public void ClosePersistent(ProgressInfo notification, string title, string message)
        {
            notification.Report((100, message, title, false));
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
                Width = 400,
                Height = 180,
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
                Margin = new Thickness(0, 0, 0, 10),
                TextWrapping = System.Windows.TextWrapping.Wrap
            };
            System.Windows.Controls.Grid.SetRow(promptText, 0);

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
            var okButton = new System.Windows.Controls.Button { Content = "OK", Width = 75, Margin = new Thickness(0, 0, 10, 0) };
            var cancelButton = new System.Windows.Controls.Button { Content = "Отмена", Width = 75 };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            System.Windows.Controls.Grid.SetRow(buttonPanel, 2);

            grid.Children.Add(promptText);
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
    }
}