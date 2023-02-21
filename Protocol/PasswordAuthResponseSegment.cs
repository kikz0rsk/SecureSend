using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class PasswordAuthResponseSegment : NetworkSegment
    {
        byte[] passwordHash;
        string salt;
        string username;

        public PasswordAuthResponseSegment(string username, byte[] passwordHash, string salt) : base(SegmentType.PASSWORD_AUTH_RESP)
        {
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.username = username;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeVarLengthString(this.username)
                .Concat(EncodeVarLengthBytes(this.passwordHash))
                .Concat(EncodeVarLengthString(this.salt)).ToArray();
        }

        public static PasswordAuthResponseSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            string username = decoder.DecodeVarLengthString(payloadBytes);
            byte[] hash = decoder.DecodeVarLengthBytes(payloadBytes);
            string salt = decoder.DecodeVarLengthString(payloadBytes);

            return new PasswordAuthResponseSegment(username, hash, salt);
        }

        public byte[] PasswordHash { get { return passwordHash; } }
        public string Salt { get { return salt; } }
        public string Username { get { return username; } }

    }
}
