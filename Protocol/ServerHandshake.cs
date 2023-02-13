using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ServerHandshake : Packet
    {
        protected byte[] publicKey;
        protected byte[] sessionId;
        protected byte[] deviceFingerprint;

        public ServerHandshake(byte[] publicKey, byte[] sessionId, byte[] deviceFingerprint) : base(PacketType.SERVER_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.sessionId = sessionId;
            this.deviceFingerprint = deviceFingerprint;
        }

        public static ServerHandshake DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            PacketDecoder decoder = new PacketDecoder();
            byte[] publicKey = decoder.DecodeFixedLengthBytes(payloadBytes, 32);
            byte[] sessionId = decoder.DecodeFixedLengthBytes(payloadBytes, 64);
            byte[] deviceFingerprint = decoder.DecodeFixedLengthBytes(payloadBytes, 32);
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
