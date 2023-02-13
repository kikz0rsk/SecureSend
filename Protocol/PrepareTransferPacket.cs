namespace SecureSend.Protocol
{
    internal class PrepareTransferPacket : Packet
    {
        public PrepareTransferPacket() : base(PacketType.PREPARE_TRANSFER)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
