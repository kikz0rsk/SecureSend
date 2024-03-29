﻿using NSec.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;

namespace SecureSend.Utils
{
    internal class CryptoUtils
    {
        private static RandomNumberGenerator secureRng = RandomNumberGenerator.Create();
        private static Random rng = new Random();

        public static KeyCreationParameters AllowExport()
        {
            KeyCreationParameters paramz = new KeyCreationParameters();
            paramz.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            return paramz;
        }

        public static void FillWithRandomBytes(byte[] array)
        {
            secureRng.GetBytes(array);
        }

        public static byte[] EncryptBytes(byte[] plaintext, Key symmetricKey, byte[] nonce)
        {
            return AeadAlgorithm.Aes256Gcm.Encrypt(symmetricKey, nonce, null, plaintext);
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

        public static string CreateRandomString(int length)
        {
            const string chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            char[] salt = new char[length];

            for (int i = 0; i < length; i++)
            {
                salt[i] = chars[rng.Next(0, chars.Length)];
            }

            return new string(salt);
        }

        public static Random GetRandomInstance()
        {
            return rng;
        }
    }
}
