using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class FileInfoSegment : Segment
    {
        public FileInfoSegment(string fileName, ulong fileSize, byte[] hash)
            : base(SegmentType.FILE_INFO)
        {
            FileName = fileName;
            FileSize = fileSize;
            Hash = hash;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeULong(FileSize)
                .Concat(Hash)
                .Concat(EncodeVarLengthString(FileName))
                .ToArray();
        }

        public static FileInfoSegment DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            SegmentDecoder decoder = new SegmentDecoder();
            ulong fileSize = decoder.DecodeULong(payloadBytes);
            byte[] hash = decoder.DecodeFixedLengthBytes(payloadBytes, 16);
            string filename = decoder.DecodeVarLengthString(payloadBytes);
            return new FileInfoSegment(filename, fileSize, hash);
        }

        public string FileName { get; private set; }

        public ulong FileSize { get; private set; }

        public byte[] Hash { get; private set; }
    }
}
