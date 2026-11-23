using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using MIGA_Agent.Models;
using ZXing;
using ZXing.Common;

namespace MIGA_Agent.Services;

public static class InvitationQrReader
{
    public static string Read(string file)
    {
        if (new FileInfo(file).Length > 16 * 1024 * 1024) throw new InvalidDataException("Изображение слишком большое.");
        using var stream = File.OpenRead(file);
        var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];
        if (frame.PixelWidth <= 0 || frame.PixelHeight <= 0 || (long)frame.PixelWidth * frame.PixelHeight > 16000000)
            throw new InvalidDataException("Изображение слишком большое.");
        var bitmap = new FormatConvertedBitmap(frame, PixelFormats.Bgr24, null, 0);
        int stride = checked(bitmap.PixelWidth * 3);
        var pixels = new byte[checked(stride * bitmap.PixelHeight)];
        bitmap.CopyPixels(pixels, stride, 0);
        var luminance = new RGBLuminanceSource(pixels, bitmap.PixelWidth, bitmap.PixelHeight, RGBLuminanceSource.BitmapFormat.BGR24);
        var reader = new BarcodeReaderGeneric { AutoRotate = true, Options = new DecodingOptions { TryHarder = true, PossibleFormats = [BarcodeFormat.QR_CODE] } };
        string invitation = reader.Decode(luminance)?.Text?.Trim() ?? throw new InvalidDataException("QR-код не найден.");
        ProtocolV2Invitation.Parse(invitation);
        return invitation;
    }
}
