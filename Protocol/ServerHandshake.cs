using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class ServerHandshake : Packet
    {
        protected byte[] publicKey;
        protected byte[] sessionId;

        public ServerHandshake(byte[] publicKey, byte[] sessionId) : base(Type.SERVER_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.sessionId = sessionId;
        }

        public static ServerHandshake DecodeFromBytes(byte[] payloadBytes)
        {
            byte[] publicKey = payloadBytes.Take(32).ToArray();
            byte[] sessionId = payloadBytes.Skip(32).Take(64).ToArray();
            return new ServerHandshake(publicKey, sessionId);
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(sessionId).ToArray();
        }
    }
}
