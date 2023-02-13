namespace SecureSend.Protocol
{
    internal class HeartbeatPacket : Packet
    {
        public HeartbeatPacket() : base(PacketType.HEARTBEAT)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
