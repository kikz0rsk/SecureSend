using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class HeartbeatPacket : Packet
    {
        public HeartbeatPacket() : base(Type.HEARTBEAT)
        { }

        protected override byte[] SerializePayload()
        {
            return new byte[0];
        }
    }
}
