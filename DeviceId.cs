using NSec.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP
{
    public class DeviceId
    {
        private string ip;
        private PublicKey publicKey;

        public string Ip { get => ip; set => ip = value; }
        public PublicKey PublicKey { get => publicKey; }

        public DeviceId(string ip, PublicKey publicKey)
        {
            this.ip = ip;
            this.publicKey = publicKey;
        }
    }
}
