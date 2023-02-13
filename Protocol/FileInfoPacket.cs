﻿using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class FileInfoPacket : Packet
    {
        string fileName;
        ulong fileSize;
        byte[] hash;

        public FileInfoPacket(string fileName, ulong fileSize, byte[] hash) : base(PacketType.FILE_INFO)
        {
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.hash = hash;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeULong(this.fileSize).Concat(hash).Concat(EncodeVarLengthString(fileName)).ToArray();
        }

        public static FileInfoPacket DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            PacketDecoder decoder = new PacketDecoder();
            ulong fileSize = decoder.DecodeULong(payloadBytes);
            byte[] hash = decoder.DecodeFixedLengthBytes(payloadBytes, 16);
            string filename = decoder.DecodeVarLengthString(payloadBytes);
            return new FileInfoPacket(filename, fileSize, hash);
        }

        public string GetFileName()
        {
            return fileName;
        }

        public ulong GetFileSize()
        {
            return fileSize;
        }

        public byte[] GetHash() {
            return hash;
        }
    }
}
