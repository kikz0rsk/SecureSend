using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal abstract class Packet
    {
        protected Type type;

        public Packet(Type type)
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
            Type? typeCode = (Type)packetBytes[0];

            var payload = packetBytes.Skip(1);
            switch (typeCode)
            {
                case Type.DATA:
                    return new DataPacket(payload.ToArray());
                case Type.FILE_INFO:
                    return FileInfoPacket.DecodeFromBytes(payload.ToArray());
                case Type.HEARTBEAT:
                    return new HeartbeatPacket();
                case Type.ACK:
                    return new AckPacket();
                case Type.NACK:
                    return new NackPacket();
                case Type.DISCONNECT:
                    return new DisconnectPacket();
                case Type.SERVER_HANDSHAKE:
                    return ServerHandshake.DecodeFromBytes(payload.ToArray());
                case Type.CLIENT_HANDSHAKE:
                    return ClientHandshake.DecodeFromBytes(payload.ToArray());
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

        public static byte[] DecodeVarLengthBytes(byte[] bytes)
        {
            int length = DecodeInteger(bytes.Take(4).ToArray());
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

        public enum Type
        {
            SERVER_HANDSHAKE = 0,
            CLIENT_HANDSHAKE = 1,
            FILE_INFO = 2, 
            DATA = 3,
            HEARTBEAT = 4,
            ACK = 5,
            NACK = 6,
            DISCONNECT = 7,
            STOP = 8
        }

        public Type GetType()
        {
            return type;
        }
    }
}
