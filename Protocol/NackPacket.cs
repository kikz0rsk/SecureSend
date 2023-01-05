using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class NackPacket : Packet
    {
        public NackPacket() : base(Type.NACK)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
