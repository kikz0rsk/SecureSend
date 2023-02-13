namespace SecureSend.Protocol
{
    internal class AckPacket : Packet
    {
        public AckPacket() : base(PacketType.ACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
