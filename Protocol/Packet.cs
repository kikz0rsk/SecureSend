using SecureSend.Utils;
using System;
using System.Linq;
using System.Text;

namespace SecureSend.Protocol
{
    public abstract class Packet
    {
        protected PacketType type;

        public Packet(PacketType type)
        {
            this.type = type;
        }

        public byte[] BuildPacket()
        {
            byte[] payload = EncodePayload();
            byte[] output = {(byte)type};
            return output.Concat(payload).ToArray();
        }

        protected abstract byte[] EncodePayload();

        public static Packet? Deserialize(ReadOnlySpan<byte> packetBytes) {
            PacketType? typeCode = (PacketType)packetBytes[0];

            var payload = packetBytes.Slice(1);
            switch (typeCode)
            {
                case PacketType.DATA:
                    return new DataPacket(payload);
                case PacketType.FILE_INFO:
                    return FileInfoPacket.DecodeFromBytes(payload);
                case PacketType.PREPARE_TRANSFER:
                    return new PrepareTransferPacket();
                case PacketType.ACK:
                    return new AckPacket();
                case PacketType.NACK:
                    return new NackPacket();
                case PacketType.SERVER_HANDSHAKE:
                    return ServerHandshake.DecodeFromBytes(payload);
                case PacketType.CLIENT_HANDSHAKE:
                    return ClientHandshake.DecodeFromBytes(payload);
                case PacketType.PASSWORD_AUTH_REQ:
                    return new PasswordAuthRequestPacket();
                case PacketType.PASSWORD_AUTH_RESP:
                    return PasswordAuthPacket.DecodeFromBytes(payload);
                default:
                    return null;
            }
        }

        public static byte[] EncodeInteger(int number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static int DecodeInteger(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 4).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }

        public static byte[] EncodeUShort(ushort number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ushort DecodeUShort(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 2).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt16(bytes, 0);
        }

        public static byte[] EncodeULong(ulong number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ulong DecodeULong(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 8).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt64(bytes, 0);
        }

        public static byte[] EncodeVarLengthBytes(byte[] bytes)
        {
            byte[] encodedLength = EncodeInteger(bytes.Length);
            return encodedLength.Concat(bytes).ToArray();
        }

        public static byte[] DecodeVarLengthBytes(ReadOnlySpan<byte> input, out int skipBytes)
        {
            int length = DecodeInteger(input);
            skipBytes = 4 + length;
            return input.Slice(4, length).ToArray();
        }

        public static byte[] EncodeVarLengthString(string str)
        {
            byte[] encodedLength = EncodeInteger(str.Length);
            return encodedLength.Concat(UTF8Encoding.UTF8.GetBytes(str)).ToArray();
        }

        public static string DecodeVarLengthString(ReadOnlySpan<byte> input, out int skipBytes)
        {
            int length = DecodeInteger(input);
            skipBytes = 4 + length;
            return UTF8Encoding.UTF8.GetString(input.Slice(4, length));
        }

        public static string DecodeVarLengthString(ReadOnlySpan<byte> input)
        {
            int length = DecodeInteger(input);
            return UTF8Encoding.UTF8.GetString(input.Slice(4, length));
        }

        public PacketType GetPacketType()
        {
            return type;
        }
    }
}
