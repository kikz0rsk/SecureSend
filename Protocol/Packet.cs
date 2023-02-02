using Org.BouncyCastle.Utilities;
using SecureSend.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal abstract class Packet
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

        public static Packet? Deserialize(byte[] packetBytes) {
            PacketType? typeCode = (PacketType)packetBytes[0];

            var payload = packetBytes.Skip(1);
            switch (typeCode)
            {
                case PacketType.DATA:
                    return new DataPacket(payload.ToArray());
                case PacketType.FILE_INFO:
                    return FileInfoPacket.DecodeFromBytes(payload.ToArray());
                case PacketType.HEARTBEAT:
                    return new HeartbeatPacket();
                case PacketType.ACK:
                    return new AckPacket();
                case PacketType.NACK:
                    return new NackPacket();
                case PacketType.DISCONNECT:
                    return new DisconnectPacket();
                case PacketType.SERVER_HANDSHAKE:
                    return ServerHandshake.DecodeFromBytes(payload.ToArray());
                case PacketType.CLIENT_HANDSHAKE:
                    return ClientHandshake.DecodeFromBytes(payload.ToArray());
                case PacketType.PASSWORD_AUTH_REQ:
                    return new PasswordAuthRequestPacket();
                case PacketType.PASSWORD_AUTH_RESP:
                    return PasswordAuthPacket.DecodeFromBytes(payload.ToArray());
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

        public static int DecodeInteger(byte[] bytes)
        {
            bytes = bytes.Take(4).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }

        public static byte[] EncodeUShort(ushort number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ushort DecodeUShort(byte[] bytes)
        {
            bytes = bytes.Take(2).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt16(bytes, 0);
        }

        public static byte[] EncodeULong(ulong number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ulong DecodeULong(byte[] bytes)
        {
            bytes = bytes.Take(8).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt64(bytes, 0);
        }

        public static byte[] EncodeVarLengthBytes(byte[] bytes)
        {
            byte[] encodedLength = EncodeInteger(bytes.Length);
            return encodedLength.Concat(bytes).ToArray();
        }

        public static byte[] DecodeVarLengthBytes(byte[] bytes, out int skipBytes)
        {
            int length = DecodeInteger(bytes.Take(4).ToArray());
            skipBytes = 4 + length;
            return bytes.Skip(4).Take(length).ToArray();
        }

        public static byte[] EncodeVarLengthString(string str)
        {
            byte[] encodedLength = EncodeInteger(str.Length);
            return encodedLength.Concat(UTF8Encoding.UTF8.GetBytes(str)).ToArray();
        }

        public static string DecodeVarLengthString(byte[] bytes, out int skipBytes)
        {
            int length = DecodeInteger(bytes.Take(4).ToArray());
            skipBytes = 4 + length;
            return UTF8Encoding.UTF8.GetString(bytes.Skip(4).Take(length).ToArray());
        }

        public static string DecodeVarLengthString(byte[] bytes)
        {
            int length = DecodeInteger(bytes.Take(4).ToArray());
            return UTF8Encoding.UTF8.GetString(bytes.Skip(4).Take(length).ToArray());
        }

        public PacketType GetType()
        {
            return type;
        }
    }
}
