using NSec.Cryptography;
using System;
using System.IO;
using SecureSend.Utils;

namespace SecureSend.Base
{
    internal class IdentityManager
    {
        private static IdentityManager instance;

        private Key key;

        public static IdentityManager Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new IdentityManager();
                }
                return instance;
            }

            private set { }
        }

        private IdentityManager()
        { }

        public void LoadKey()
        {
            if (File.Exists(".id"))
            {
                byte[] key = File.ReadAllBytes(".id");
                try
                {
                    this.key = Key.Import(KeyAgreementAlgorithm.X25519, key, KeyBlobFormat.RawPrivateKey, CryptoUtils.AllowExport());
                    return;
                }
                catch (Exception)
                { }
            }

            key = Key.Create(KeyAgreementAlgorithm.X25519, CryptoUtils.AllowExport());
            SaveKey();
        }

        public void SaveKey()
        {
            using (FileStream fs = new FileStream(".id", FileMode.Create))
            {
                byte[] keyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
                fs.Write(keyBytes, 0, keyBytes.Length);
            }
        }

        public Key GetKey()
        {
            if (key == null)
            {
                LoadKey();
            }

            return key;
        }
    }
}
