using SecureSend.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Utils
{
    internal class PacketDecoder
    {
        private int offset;

        public PacketDecoder()
        {
            offset = 0;
        }

        public int DecodeInteger(ReadOnlySpan<byte> input)
        {
            int num = Packet.DecodeInteger(input.Slice(offset));
            offset += 4;
            return num;
        }

        public ushort DecodeUShort(ReadOnlySpan<byte> input)
        {
            ushort num = Packet.DecodeUShort(input.Slice(offset));
            offset += 2;
            return num;
        }

        public ulong DecodeULong(ReadOnlySpan<byte> input)
        {
            ulong num = Packet.DecodeULong(input.Slice(offset));
            offset += 8;
            return num;
        }

        public byte[] DecodeVarLengthBytes(ReadOnlySpan<byte> input)
        {
            int length = DecodeInteger(input);
            byte[] arr = input.Slice(offset, length).ToArray();
            offset += length;
            return arr;
        }

        public byte[] DecodeFixedLengthBytes(ReadOnlySpan<byte> input, int length)
        {
            byte[] arr = input.Slice(offset, length).ToArray();
            offset += length;
            return arr;
        }

        public string DecodeVarLengthString(ReadOnlySpan<byte> input)
        {
            int length = DecodeInteger(input);
            string output = Encoding.UTF8.GetString(input.Slice(offset, length));
            offset += length;
            return output;
        }

        public string DecodeFixedLengthString(ReadOnlySpan<byte> input, int length)
        {
            string output = Encoding.UTF8.GetString(input.Slice(offset, length));
            offset += length;
            return output;
        }

    }
}
