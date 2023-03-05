using SecureSend.Protocol;
using System;
using System.Text;

namespace SecureSend.Utils
{
    internal class SegmentDecoder
    {
        private int offset;

        public SegmentDecoder()
        {
            offset = 0;
        }

        public int DecodeInteger(ReadOnlySpan<byte> input)
        {
            int num = Segment.DecodeInteger(input.Slice(offset));
            offset += 4;
            return num;
        }

        public ushort DecodeUShort(ReadOnlySpan<byte> input)
        {
            ushort num = Segment.DecodeUShort(input.Slice(offset));
            offset += 2;
            return num;
        }

        public ulong DecodeULong(ReadOnlySpan<byte> input)
        {
            ulong num = Segment.DecodeULong(input.Slice(offset));
            offset += 8;
            return num;
        }

        public byte[] DecodeVarLengthBytes(ReadOnlySpan<byte> input)
        {
            int skip;
            byte[] bytes = Segment.DecodeVarLengthBytes(input.Slice(offset), out skip);
            offset += skip;
            return bytes;
        }

        public byte[] DecodeFixedLengthBytes(ReadOnlySpan<byte> input, int length)
        {
            byte[] arr = input.Slice(offset, length).ToArray();
            offset += length;
            return arr;
        }

        public string DecodeVarLengthString(ReadOnlySpan<byte> input)
        {
            int skip;
            string str = Segment.DecodeVarLengthString(input.Slice(offset), out skip);
            offset += skip;
            return str;
        }

        public string DecodeFixedLengthString(ReadOnlySpan<byte> input, int length)
        {
            string output = Encoding.UTF8.GetString(input.Slice(offset, length));
            offset += length;
            return output;
        }

    }
}
