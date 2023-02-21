namespace SecureSend.Protocol
{
    internal class NackSegment : NetworkSegment
    {
        public NackSegment() : base(SegmentType.NACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
