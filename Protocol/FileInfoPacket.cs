﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class FileInfoPacket : Packet
    {
        string fileName;
        ulong fileSize;
        byte[] hash;

        public FileInfoPacket(string fileName, ulong fileSize, byte[] hash) : base(Type.FILE_INFO)
        {
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.hash = hash;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeULong(this.fileSize).Concat(hash).Concat(EncodeVarLengthString(fileName)).ToArray();
        }

        public static FileInfoPacket DecodeFromBytes(byte[] payloadBytes)
        {
            ulong fileSize = DecodeULong(payloadBytes.Take(8).ToArray());
            byte[] hash = payloadBytes.Skip(8).Take(16).ToArray();
            string filename = DecodeVarLengthString(payloadBytes.Skip(24).ToArray());
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
