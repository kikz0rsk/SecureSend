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
    }
}
