using System;
using System.Collections.Generic;
using System.Linq;

namespace BP.Protocol
{
    internal class ClientHandshake : Packet
    {
        byte[] publicKey;
        byte encryptionAlgo;

        public ClientHandshake(byte[] publicKey, byte encryptionAlgo) : base(Type.CLIENT_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.encryptionAlgo = encryptionAlgo;
        }

        public static ClientHandshake DecodeFromBytes(byte[] payloadBytes)
        {
            return new ClientHandshake(payloadBytes.Take(32).ToArray(), 0);
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(new byte[] { encryptionAlgo }).ToArray();
        }
    }
}
