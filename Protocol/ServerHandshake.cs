using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ServerHandshake : Segment
    {
        public ServerHandshake(byte[] publicKey, byte[] sessionId,
            byte[] deviceFingerprint, string computerName) : base(SegmentType.SERVER_HANDSHAKE)
        {
            PublicKey = publicKey;
            SessionId = sessionId;
            DeviceFingerprint = deviceFingerprint;
            ComputerName = computerName;
        }

        public static ServerHandshake DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            byte[] publicKey = decoder.DecodeFixedLengthBytes(payloadBytes, 32);
            byte[] sessionId = decoder.DecodeFixedLengthBytes(payloadBytes, 64);
            byte[] deviceFingerprint = decoder.DecodeFixedLengthBytes(payloadBytes, 32);
            string computerName = decoder.DecodeVarLengthString(payloadBytes);
            return new ServerHandshake(publicKey, sessionId, deviceFingerprint, computerName);
        }

        protected override byte[] EncodePayload()
        {
            return PublicKey
                .Concat(SessionId)
                .Concat(DeviceFingerprint)
                .Concat(EncodeVarLengthString(ComputerName))
                .ToArray();
        }

        public byte[] PublicKey { get; protected set; }

        public byte[] SessionId { get; protected set; }

        public byte[] DeviceFingerprint { get; protected set; }

        public string ComputerName { get; protected set; }
    }
}
