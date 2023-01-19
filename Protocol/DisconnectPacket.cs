using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal class DisconnectPacket : Packet
    {
        public DisconnectPacket() : base(Type.DISCONNECT)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
