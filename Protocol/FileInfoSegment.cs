using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class FileInfoSegment : Segment
    {
        string fileName;
        ulong fileSize;
        byte[] hash;

        public FileInfoSegment(string fileName, ulong fileSize, byte[] hash) : base(SegmentType.FILE_INFO)
        {
            this.fileName = fileName;
            this.fileSize = fileSize;
            this.hash = hash;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeULong(this.fileSize).Concat(hash).Concat(EncodeVarLengthString(fileName)).ToArray();
        }

        public static FileInfoSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            ulong fileSize = decoder.DecodeULong(payloadBytes);
            byte[] hash = decoder.DecodeFixedLengthBytes(payloadBytes, 16);
            string filename = decoder.DecodeVarLengthString(payloadBytes);
            return new FileInfoSegment(filename, fileSize, hash);
        }

        public string GetFileName()
        {
            return fileName;
        }

        public ulong GetFileSize()
        {
            return fileSize;
        }

        public byte[] GetHash()
        {
            return hash;
        }
    }
}
