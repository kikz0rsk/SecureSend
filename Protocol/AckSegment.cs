namespace SecureSend.Protocol
{
    internal class AckSegment : NetworkSegment
    {
        public AckSegment() : base(SegmentType.ACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
