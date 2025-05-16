using System;
using System.IO;
using System.Threading.Tasks;
using QRCoder;
using OtpNet;
using CompAuthApi.Core.Abstractions;

namespace CompAuthApi.Core.Repositories
{
    public class QrCodeRepository : IQrCodeRepository
    {
        private readonly string _qrCodeDirectory;

        public QrCodeRepository()
        {
            _qrCodeDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Attachments");

            if (!Directory.Exists(_qrCodeDirectory))
            {
                Directory.CreateDirectory(_qrCodeDirectory);
            }
        }

        public async Task<string> GenerateAndSaveQrCodeAsync(string email, string secretKey)
        {
            string base32Secret = secretKey.TrimEnd('=');

            var issuer = "CompAuthApi";
            var totpUrl = $"otpauth://totp/{issuer}:{email}?secret={base32Secret}&issuer={issuer}";

            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(totpUrl, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            byte[] qrCodeBytes = qrCode.GetGraphic(20);

            string fileName = $"{email.Replace("@", "_").Replace(".", "_")}_2FA.png";
            string filePath = Path.Combine(_qrCodeDirectory, fileName);

            await File.WriteAllBytesAsync(filePath, qrCodeBytes);

            return fileName;
        }

        public async Task<byte[]> GetQrCodeAsync(string fileName)
        {
            string filePath = Path.Combine(_qrCodeDirectory, fileName);

            if (!File.Exists(filePath))
                return Array.Empty<byte>();

            return await File.ReadAllBytesAsync(filePath);
        }

        public async Task<bool> DeleteQrCodeAsync(string fileName)
        {
            string filePath = Path.Combine(_qrCodeDirectory, fileName);

            if (!File.Exists(filePath))
                return false;

            await Task.Run(() => File.Delete(filePath));
            return true;
        }
    }
}
