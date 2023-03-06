using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ClientHandshake : Segment
    {
        public ClientHandshake(byte[] publicKey, byte[] hardwareFingerprint, string computerName) :
            base(SegmentType.CLIENT_HANDSHAKE)
        {
            PublicKey = publicKey;
            HardwareFingerprint = hardwareFingerprint;
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
                .Concat(HardwareFingerprint)
                .Concat(EncodeVarLengthString(ComputerName))
                .ToArray();
        }

        public byte[] PublicKey { get; protected set; }

        public byte[] HardwareFingerprint { get; protected set; }

        public string ComputerName { get; protected set; }
    }
}
