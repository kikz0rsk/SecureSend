namespace SecureSend.Protocol
{
    internal class AckSegment : Segment
    {
        public AckSegment() : base(SegmentType.ACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
