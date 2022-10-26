﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using BP.Protocol;
using NSec.Cryptography;

namespace BP.Networking
{
    internal class NetworkEndpoint
    {
        protected Key? symmetricKey;
        protected NetworkStream stream;
        protected ConcurrentQueue<string> filesToSend = new ConcurrentQueue<string>();
        protected MainWindow mainWindow;

        protected void SendPacket(Packet packet)
        {
            byte[] nonce;
            byte[] serializedPacket = packet.Serialize();
            byte[] encryptedPayload = CryptoUtils.EncryptBytes(serializedPacket, symmetricKey, out nonce);
            byte[] packetLengthBytes = BitConverter.GetBytes(Convert.ToUInt16(encryptedPayload.Length + 12)); // Nonce is 12 bytes
            NetworkUtils.EnsureCorrectEndianness(packetLengthBytes);
            byte[] bytesToSend = packetLengthBytes.Concat(nonce).Concat(encryptedPayload).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Packet? ReceivePacket()
        {
            byte[] packetLengthRaw = NetworkUtils.ReadExactlyBytes(stream, 2);
            NetworkUtils.EnsureCorrectEndianness(packetLengthRaw);
            uint packetLength = BitConverter.ToUInt16(packetLengthRaw, 0);

            byte[] encryptedPacket = NetworkUtils.ReadExactlyBytes(stream, packetLength);

            byte[] nonce = encryptedPacket.Take(12).ToArray();
            byte[] payload = encryptedPacket.Skip(12).ToArray();
            byte[]? decryptedPacketBytes = CryptoUtils.DecryptBytes(payload, symmetricKey, nonce);

            if (decryptedPacketBytes == null) throw new InvalidDataException("Could not decrypt packet");

            Packet? packet = Packet.Deserialize(decryptedPacketBytes);

            if (packet == null) throw new InvalidDataException("Could not deserialize packet");

            return packet;
        }

        protected Key? EstablishTrust()
        {
            // send public key
            stream.Write(mainWindow.ClientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0, 32);

            // get client's public key
            byte[] otherEndpointPublicKey = new byte[32];
            stream.Read(otherEndpointPublicKey, 0, 32);

            PublicKey serverPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, otherEndpointPublicKey, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret sharedSecret = KeyAgreementAlgorithm.X25519.Agree(mainWindow.ClientKeyPair, serverPublicKey);

            if (sharedSecret == null)
            {
                return null;
            }

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, null, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        public ConcurrentQueue<string> GetFilesToSend()
        {
            return filesToSend;
        }
    }
}