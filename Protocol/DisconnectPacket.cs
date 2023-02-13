namespace SecureSend.Protocol
{
    internal class DisconnectPacket : Packet
    {
        public DisconnectPacket() : base(PacketType.DISCONNECT)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
