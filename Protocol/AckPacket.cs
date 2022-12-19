using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class AckPacket : Packet
    {
        public AckPacket() : base(Type.ACK)
        { }

        protected override byte[] SerializePayload()
        {
            return new byte[0];
        }
    }
}
