using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ClientHandshake : NetworkSegment
    {
        public ClientHandshake(byte[] publicKey, byte[] deviceFingerprint, string computerName) :
            base(SegmentType.CLIENT_HANDSHAKE)
        {
            PublicKey = publicKey;
            DeviceFingerprint = deviceFingerprint;
            ComputerName = computerName;
        }

        public static ClientHandshake DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            return new ClientHandshake(
                decoder.DecodeFixedLengthBytes(payloadBytes, 32),
                decoder.DecodeFixedLengthBytes(payloadBytes, 32),
                decoder.DecodeVarLengthString(payloadBytes)
            );
        }

        protected override byte[] EncodePayload()
        {
            return PublicKey
                .Concat(DeviceFingerprint)
                .Concat(EncodeVarLengthString(ComputerName))
                .ToArray();
        }

        public byte[] PublicKey { get; protected set; }

        public byte[] DeviceFingerprint { get; protected set; }

        public string ComputerName { get; protected set; }
    }
}
