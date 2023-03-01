using System;

namespace SecureSend.Protocol
{
    internal class DataSegment : Segment
    {

        public DataSegment(byte[] data) : base(SegmentType.DATA)
        {
            Data = data;
        }

        public DataSegment(ReadOnlySpan<byte> data) : this(data.ToArray())
        { }

        protected override byte[] EncodePayload()
        {
            return Data;
        }

        public byte[] Data { get; private set; }

    }
}
