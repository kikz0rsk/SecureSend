using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            ulong fileSize = DecodeULong(payloadBytes.Slice(0, 8).ToArray());
            byte[] hash = payloadBytes.Slice(8, 16).ToArray();
            string filename = DecodeVarLengthString(payloadBytes.Slice(24).ToArray());
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
