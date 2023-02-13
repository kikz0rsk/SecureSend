using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ClientHandshake : Packet
    {
        byte[] publicKey;
        byte encryptionAlgo;
        byte[] deviceFingerprint;

        public ClientHandshake(byte[] publicKey, byte encryptionAlgo,
            byte[] deviceFingerprint) : base(PacketType.CLIENT_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.encryptionAlgo = encryptionAlgo;
            this.deviceFingerprint = deviceFingerprint;
        }

        public static ClientHandshake DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            PacketDecoder decoder = new PacketDecoder();
            return new ClientHandshake(
                decoder.DecodeFixedLengthBytes(payloadBytes, 32),
                0,
                decoder.DecodeFixedLengthBytes(payloadBytes, 32)
            );
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(deviceFingerprint).ToArray();
        }

        public byte[] PublicKey { get { return publicKey; } }

        public byte EncryptionAlgo { get { return encryptionAlgo; } }

        public byte[] DeviceFingerprint { get { return deviceFingerprint; } }
    }
}
