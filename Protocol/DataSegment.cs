using System;

namespace SecureSend.Protocol
{
    internal class DataSegment : Segment
    {
        protected byte[] data;

        public DataSegment(byte[] data) : base(SegmentType.DATA)
        {
            this.data = data;
        }

        public DataSegment(ReadOnlySpan<byte> data) : this(data.ToArray())
        { }

        protected override byte[] EncodePayload()
        {
            return data;
        }

        public byte[] GetData()
        {
            return data;
        }

    }
}
