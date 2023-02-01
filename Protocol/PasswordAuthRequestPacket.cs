using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal class PasswordAuthRequestPacket : Packet
    {
        public PasswordAuthRequestPacket() : base(Type.PASSWORD_AUTH_REQ)
        { }

        protected override byte[] EncodePayload()
        {
            return new byte[0];
        }
    }
}
