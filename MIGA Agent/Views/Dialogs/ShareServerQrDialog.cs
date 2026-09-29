using QRCoder;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace MIGA_Agent.Views.Dialogs
{
    public sealed class ShareServerQrDialog : Window
    {
        public ShareServerQrDialog(string payload)
        {
            Title = "Поделиться настройками сервера";
            Width = 420;
            Height = 540;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            using var generator = new QRCodeGenerator();
            using var data = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.M);
            using var qr = new PngByteQRCode(data);
            var bitmap = new BitmapImage();
            using (var stream = new MemoryStream(qr.GetGraphic(6)))
            {
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.StreamSource = stream;
                bitmap.EndInit();
                bitmap.Freeze();
            }

            var panel = new StackPanel { Margin = new Thickness(20) };
            panel.Children.Add(new TextBlock
            {
                Text = "QR-код содержит адрес, порты и ключи сервера. Показывайте его только доверенному получателю.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 12)
            });
            var image = new Image { Source = bitmap, Width = 350, Height = 350 };
            RenderOptions.SetBitmapScalingMode(image, BitmapScalingMode.NearestNeighbor);
            panel.Children.Add(image);
            var close = new Button { Content = "Закрыть", Width = 100, Margin = new Thickness(0, 12, 0, 0) };
            close.Click += (_, _) => Close();
            panel.Children.Add(close);
            Content = panel;
        }
    }
}
