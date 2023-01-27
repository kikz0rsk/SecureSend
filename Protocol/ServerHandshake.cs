using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal class ServerHandshake : Packet
    {
        protected byte[] publicKey;
        protected byte[] sessionId;
        protected byte[] deviceFingerprint;

        public ServerHandshake(byte[] publicKey, byte[] sessionId, byte[] deviceFingerprint) : base(Type.SERVER_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.sessionId = sessionId;
            this.deviceFingerprint = deviceFingerprint;
        }

        public static ServerHandshake DecodeFromBytes(byte[] payloadBytes)
        {
            byte[] publicKey = payloadBytes.Take(32).ToArray();
            byte[] sessionId = payloadBytes.Skip(32).Take(64).ToArray();
            byte[] deviceFingerprint = payloadBytes.Skip(96).ToArray();
            return new ServerHandshake(publicKey, sessionId, deviceFingerprint);
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(sessionId).Concat(deviceFingerprint).ToArray();
        }

        public byte[] PublicKey { get { return publicKey; } }

        public byte[] SessionId { get { return sessionId; } }

        public byte[] DeviceFingerprint { get { return deviceFingerprint; } }
    }
}
