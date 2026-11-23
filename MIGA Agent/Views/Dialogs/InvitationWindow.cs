using Microsoft.Win32;
using MIGA_Agent.Models;
using QRCoder;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace MIGA_Agent.Views.Dialogs;

public sealed class InvitationWindow : Window
{
    private readonly TextBox invitation = new() { AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxLength = 4096 };
    private readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap };
    private readonly Image image = new() { MaxWidth = 304, MaxHeight = 304, Stretch = Stretch.Uniform, Margin = new Thickness(0, 8, 0, 0) };

    public InvitationWindow(Func<string, Task>? apply, bool sharing, string value = "", bool openInClient = false)
    {
        Title = sharing ? "Поделиться приглашением MIGA" : "Применить приглашение MIGA";
        Width = sharing ? 560 : 520;
        MinWidth = 390;
        MinHeight = 255;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var instructions = new TextBlock { Text = sharing
            ? "Это приглашение даёт сетевой доступ своему владельцу, без административных прав. Для другого устройства создайте отдельное приглашение в MIGA Admin. Правила перенаправления в приглашение не входят. Передавайте его только получателю."
            : "Вставьте приглашение для текущего подключения. Правила перенаправления сохранятся.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) };
        invitation.Text = value;
        invitation.IsReadOnly = sharing && value.Length > 0;
        var actions = new WrapPanel();
        var statusView = new ScrollViewer
        {
            Content = status,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Visibility = Visibility.Collapsed,
            MaxHeight = 72
        };
        Panel panel;
        if (sharing)
        {
            MaxHeight = Math.Max(MinHeight, SystemParameters.WorkArea.Height);
            SizeToContent = SizeToContent.Height;
            invitation.Height = 100;
            actions.Margin = new Thickness(0, 8, 0, 0);
            instructions.Margin = new Thickness(0, 0, 0, 12);
            var sharePanel = new StackPanel { Margin = new Thickness(16) };
            sharePanel.Children.Add(instructions);
            sharePanel.Children.Add(invitation);
            sharePanel.Children.Add(actions);
            sharePanel.Children.Add(statusView);
            panel = sharePanel;
            Content = new ScrollViewer { Content = sharePanel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, PanningMode = PanningMode.VerticalOnly };
        }
        else
        {
            Height = 255;
            invitation.Padding = new Thickness(8, 5, 8, 5);
            var importPanel = new Grid { Margin = new Thickness(16, 14, 16, 14) };
            importPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            importPanel.RowDefinitions.Add(new RowDefinition());
            importPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            importPanel.Children.Add(instructions);
            Grid.SetRow(invitation, 1);
            importPanel.Children.Add(invitation);
            var footer = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
            actions.VerticalAlignment = VerticalAlignment.Top;
            DockPanel.SetDock(actions, Dock.Left);
            footer.Children.Add(actions);
            statusView.MaxHeight = 65;
            statusView.Margin = new Thickness(6, 0, 0, 0);
            statusView.VerticalAlignment = VerticalAlignment.Center;
            footer.Children.Add(statusView);
            Grid.SetRow(footer, 2);
            importPanel.Children.Add(footer);
            panel = importPanel;
            Content = importPanel;
        }
        void SetStatus(string message)
        {
            status.Text = message;
            statusView.Visibility = message.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
            statusView.ScrollToTop();
        }
        void Add(string caption, Func<Task> action)
        {
            var button = new Button { Content = caption, Padding = new Thickness(11, 5, 11, 5), Margin = sharing ? new Thickness(0, 0, 6, 6) : new Thickness(0, 0, 6, 0) };
            button.Click += async (_, _) =>
            {
                panel.IsEnabled = false;
                try { await action(); }
                catch (Exception error)
                {
                    SetStatus(error is InvalidDataException or FileNotFoundException || openInClient && error is IOException
                        ? error.Message : "Не удалось выполнить действие. Проверьте файл, службу и права администратора.");
                }
                finally { panel.IsEnabled = true; }
            };
            actions.Children.Add(button);
        }
        if (apply != null) Add(openInClient ? "Открыть в MIGA Client" : "Применить", async () =>
        {
            await apply(Validated());
            SetStatus(openInClient ? "Приглашение открыто в MIGA Client. Подтвердите добавление в его окне." : "Приглашение сохранено, правила сохранены. Результат подключения показан в главном окне.");
        });
        if (sharing)
        {
            Add("Копировать", () => { Clipboard.SetText(Validated()); SetStatus("Приглашение скопировано."); return Task.CompletedTask; });
            Add("Сохранить файл…", async () =>
            {
                string payload = Validated();
                var dialog = new SaveFileDialog
                {
                    Title = "Сохранить приглашение",
                    FileName = "invitation.miga",
                    DefaultExt = ".miga",
                    Filter = "Приглашение MIGA (*.miga)|*.miga"
                };
                if (dialog.ShowDialog(this) == true)
                {
                    await File.WriteAllTextAsync(dialog.FileName, payload, new UTF8Encoding(false));
                    SetStatus("Приглашение сохранено. Получатель может загрузить файл или отсканировать QR.");
                }
            });
            void RenderQr()
            {
                using var generator = new QRCodeGenerator();
                using var data = generator.CreateQrCode(Validated(), QRCodeGenerator.ECCLevel.M);
                using var qr = new PngByteQRCode(data);
                var bitmap = new BitmapImage();
                using var stream = new MemoryStream(qr.GetGraphic(6));
                bitmap.BeginInit(); bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.StreamSource = stream; bitmap.EndInit(); bitmap.Freeze();
                image.Source = bitmap;
            }
            RenderQr();
            RenderOptions.SetBitmapScalingMode(image, BitmapScalingMode.NearestNeighbor);
            panel.Children.Add(image);
        }
        invitation.TextChanged += (_, _) => { image.Source = null; SetStatus(""); };
        Closed += (_, _) => { invitation.Clear(); image.Source = null; };
    }

    private string Validated()
    {
        string value = invitation.Text.Trim();
        ProtocolV2Invitation.Parse(value);
        return value;
    }
}