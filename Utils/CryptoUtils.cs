using SecureSend.Protocol;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Utils
{
    internal class CryptoUtils
    {
        private static RandomNumberGenerator rng = RandomNumberGenerator.Create();

        public static KeyCreationParameters AllowExport()
        {
            KeyCreationParameters paramz = new KeyCreationParameters();
            paramz.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            return paramz;
        }

        public static void FillWithRandomBytes(byte[] array)
        {
            rng.GetBytes(array);
        }

        public static byte[] EncryptBytes(byte[] plaintext, Key symmetricKey, out byte[] nonce)
        {
            byte[] generatedNonce = new byte[12];
            rng.GetBytes(generatedNonce);
            nonce = generatedNonce;
            return AeadAlgorithm.Aes256Gcm.Encrypt(symmetricKey, generatedNonce, null, plaintext);
        }

        public static byte[]? DecryptBytes(byte[] ciphertext, Key symmetricKey, byte[] nonce)
        {
            byte[]? plaintext = AeadAlgorithm.Aes256Gcm.Decrypt(symmetricKey, nonce, null, ciphertext);

            return plaintext;
        }

        public static byte[] CalculateFileHash(string filePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return md5.ComputeHash(stream);
                }
            }
        }
    }
}
