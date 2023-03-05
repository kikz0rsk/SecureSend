using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class PasswordAuthResponseSegment : Segment
    {
        public PasswordAuthResponseSegment(string username, byte[] passwordHash) :
            base(SegmentType.PASSWORD_AUTH_RESP)
        {
            PasswordHash = passwordHash;
            Username = username;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeVarLengthString(Username)
                .Concat(PasswordHash)
                .ToArray();
        }

        public static PasswordAuthResponseSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            string username = decoder.DecodeVarLengthString(payloadBytes);
            byte[] hash = decoder.DecodeFixedLengthBytes(payloadBytes, 32);

            return new PasswordAuthResponseSegment(username, hash);
        }

        public byte[] PasswordHash { get; private set; }
        public string Username { get; private set; }

    }
}
