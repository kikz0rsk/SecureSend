using System;

namespace SecureSend.Base
{
    class Identity
    {
        public Identity(byte[] deviceFingerprint, byte[] publicKey, string computerName)
        {
            DeviceFingerprint = deviceFingerprint;
            PublicKey = publicKey;
            ComputerName = computerName;
        }

        public byte[] DeviceFingerprint { get; private set; }
        public byte[] PublicKey { get; private set; }
        public string ComputerName { get; private set; }
        public string DeviceFingerprintString { get { return Convert.ToHexString(DeviceFingerprint); } }
        public string PublicKeyString { get { return Convert.ToBase64String(PublicKey); } }
    }
}
