using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
