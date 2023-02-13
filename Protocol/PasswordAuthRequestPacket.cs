namespace SecureSend.Protocol
{
    internal class PasswordAuthRequestPacket : Packet
    {
        public PasswordAuthRequestPacket() : base(PacketType.PASSWORD_AUTH_REQ)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
