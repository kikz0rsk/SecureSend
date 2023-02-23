﻿using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ClientHandshake : NetworkSegment
    {
        byte[] publicKey;
        byte[] deviceFingerprint;

        public ClientHandshake(byte[] publicKey, byte[] deviceFingerprint) :
            base(SegmentType.CLIENT_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.deviceFingerprint = deviceFingerprint;
        }

        public static ClientHandshake DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            return new ClientHandshake(
                decoder.DecodeFixedLengthBytes(payloadBytes, 32),
                decoder.DecodeFixedLengthBytes(payloadBytes, 32)
            );
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(deviceFingerprint).ToArray();
        }

        public byte[] PublicKey { get { return publicKey; } }

        public byte[] DeviceFingerprint { get { return deviceFingerprint; } }
    }
}
