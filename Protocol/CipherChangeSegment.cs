using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class CipherChangeSegment : Segment
    {
        public CipherChangeSegment(CipherAlgorithm algorithm, byte[] salt) : base(SegmentType.CIPHER_CHANGE)
        {
            Algorithm = algorithm;
            Salt = salt;
        }

        public static CipherChangeSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            var algo = (CipherAlgorithm)payloadBytes[0];
            byte[] salt = DecodeVarLengthBytes(payloadBytes.Slice(1).ToArray(), out _);
            return new CipherChangeSegment(algo, salt);
        }

        protected override byte[] EncodePayload()
        {
            return new byte[] { (byte)Algorithm }
                .Concat(EncodeVarLengthBytes(Salt))
                .ToArray();
        }

        public CipherAlgorithm Algorithm { get; private set; }
        public byte[] Salt { get; private set; }
    }
}
