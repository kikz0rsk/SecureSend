using System;

namespace SecureSend.Base
{
    class Identity
    {
        public Identity(byte[] hardwareFingerprint, byte[] publicKey, string computerName)
        {
            HardwareFingerprint = hardwareFingerprint;
            PublicKey = publicKey;
            ComputerName = computerName;
        }

        public byte[] HardwareFingerprint { get; private set; }
        public byte[] PublicKey { get; private set; }
        public string ComputerName { get; private set; }
        public string HardwareFingerprintString { get { return Convert.ToHexString(HardwareFingerprint); } }
        public string PublicKeyString { get { return Convert.ToBase64String(PublicKey); } }
    }
}
