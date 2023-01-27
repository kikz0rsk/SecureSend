using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Base
{
    class Identity
    {
        protected byte[] deviceFingerprint;
        protected byte[] publicKey;

        protected string deviceFingerprintString;
        protected string publicKeyString;

        public Identity(byte[] deviceFingerprint, byte[] publicKey)
        {
            this.deviceFingerprint = deviceFingerprint;
            this.deviceFingerprintString = Convert.ToHexString(deviceFingerprint);
            this.publicKey = publicKey;
            this.publicKeyString = Convert.ToHexString(publicKey);
        }

        public byte[] DeviceFingerprint { get { return deviceFingerprint; } }
        public byte[] PublicKey { get { return publicKey; } }
        public string DeviceFingerprintString { get { return deviceFingerprintString; } }
        public string PublicKeyString { get { return publicKeyString; } }
    }
}
