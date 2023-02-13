using System;

namespace SecureSend.Protocol
{
    internal class DataPacket : Packet
    {
        protected byte[] data;

        public DataPacket(byte[] data) : base(PacketType.DATA)
        {
            this.data = data;
        }

        public DataPacket(ReadOnlySpan<byte> data) : this(data.ToArray())
        { }

        protected override byte[] EncodePayload()
        {
            return data;
        }

        public byte[] GetData()
        {
            return data;
        }

    }
}
