using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class PasswordAuthResponseSegment : Segment
    {
        byte[] passwordHash;
        string username;

        public PasswordAuthResponseSegment(string username, byte[] passwordHash) :
            base(SegmentType.PASSWORD_AUTH_RESP)
        {
            this.passwordHash = passwordHash;
            this.username = username;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeVarLengthString(this.username)
                .Concat(this.passwordHash).ToArray();
        }

        public static PasswordAuthResponseSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            string username = decoder.DecodeVarLengthString(payloadBytes);
            byte[] hash = decoder.DecodeFixedLengthBytes(payloadBytes, 32);

            return new PasswordAuthResponseSegment(username, hash);
        }

        public byte[] PasswordHash { get { return passwordHash; } }
        public string Username { get { return username; } }

    }
}
