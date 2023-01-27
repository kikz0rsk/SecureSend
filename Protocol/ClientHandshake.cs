﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class ClientHandshake : Packet
    {
        byte[] publicKey;
        byte encryptionAlgo;
        byte[] deviceFingerprint;

        public ClientHandshake(byte[] publicKey, byte encryptionAlgo,
            byte[] deviceFingerprint) : base(Type.CLIENT_HANDSHAKE)
        {
            this.publicKey = publicKey;
            this.encryptionAlgo = encryptionAlgo;
            this.deviceFingerprint = deviceFingerprint;
        }

        public static ClientHandshake DecodeFromBytes(byte[] payloadBytes)
        {
            return new ClientHandshake(payloadBytes.Take(32).ToArray(), 0, payloadBytes.Skip(33).ToArray());
        }

        protected override byte[] EncodePayload()
        {
            return publicKey.Concat(new byte[] { encryptionAlgo }).Concat(deviceFingerprint).ToArray();
        }

        public byte[] PublicKey { get { return publicKey; } }

        public byte EncryptionAlgo { get { return encryptionAlgo; } }

        public byte[] DeviceFingerprint { get { return deviceFingerprint; } }
    }
}
