namespace SecureSend.Protocol
{
    internal class NackPacket : Packet
    {
        public NackPacket() : base(PacketType.NACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
