namespace SecureSend.Protocol
{
    internal class PasswordAuthRequestSegment : NetworkSegment
    {
        public PasswordAuthRequestSegment() : base(SegmentType.PASSWORD_AUTH_REQ)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
