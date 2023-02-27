using SecureSend.Utils;
using System;

namespace SecureSend.Protocol
{
    internal class PasswordAuthRequestSegment : Segment
    {
        public PasswordAuthRequestSegment(string salt) : base(SegmentType.PASSWORD_AUTH_REQ)
        {
            Salt = salt;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeVarLengthString(Salt);
        }

        public static PasswordAuthRequestSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            return new PasswordAuthRequestSegment(DecodeVarLengthString(payloadBytes));
        }

        public string Salt { get; protected set; }
    }
}
