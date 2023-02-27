namespace SecureSend.Protocol
{
    internal class NackSegment : Segment
    {
        public NackSegment() : base(SegmentType.NACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
