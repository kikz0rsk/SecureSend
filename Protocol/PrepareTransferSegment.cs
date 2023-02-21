namespace SecureSend.Protocol
{
    internal class PrepareTransferSegment : NetworkSegment
    {
        public PrepareTransferSegment() : base(SegmentType.PREPARE_TRANSFER)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
