using BP.Protocol;
using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP
{
    internal class CryptoUtils
    {
        public static KeyCreationParameters AllowExport()
        {
            KeyCreationParameters paramz = new KeyCreationParameters();
            paramz.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            return paramz;
        }

        public static byte[] EncryptBytes(byte[] plaintext, Key symmetricKey, out byte[] nonce)
        {
            byte[] generatedNonce = new byte[12];
            System.Random.Shared.NextBytes(generatedNonce);
            nonce = generatedNonce;
            return AeadAlgorithm.Aes256Gcm.Encrypt(symmetricKey, generatedNonce, null, plaintext);
        }

        public static byte[]? DecryptBytes(byte[] ciphertext, Key symmetricKey, byte[] nonce)
        {
            byte[]? plaintext = AeadAlgorithm.Aes256Gcm.Decrypt(symmetricKey, nonce, null, ciphertext);

            return plaintext;
        }
    }
}
