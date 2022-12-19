using System;
using System.Collections.Generic;
using System.Linq;
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

        public byte[] Serialize()
        {
            byte[] payload = SerializePayload();
            byte[] output = {(byte)type};
            return output.Concat(payload).ToArray();
        }

        protected abstract byte[] SerializePayload();

        public static Packet? Deserialize(byte[] packetBytes) {
            Type? opCode = (Type)packetBytes[0];

            switch (opCode)
            {
                case Type.FILE_INFO:
                    byte[] fileSizeRaw = packetBytes.Skip(1).Take(8).ToArray();
                    NetworkUtils.EnsureCorrectEndianness(fileSizeRaw);
                    ulong fileSize = BitConverter.ToUInt64(fileSizeRaw, 0);
                    byte[] hash = packetBytes.Skip(9).Take(16).ToArray();

                    string filename = UTF8Encoding.UTF8.GetString( packetBytes.Skip(25).ToArray() );
                    return new FileInfoPacket(filename, fileSize, hash);
                case Type.DATA:
                    return new DataPacket(packetBytes.Skip(1).ToArray());
                case Type.HEARTBEAT:
                    return new HeartbeatPacket();
                case Type.ACK:
                    return new AckPacket();
                case Type.NACK:
                    return new NackPacket();
                case Type.DISCONNECT:
                    return new DisconnectPacket();
                default:
                    return null;
            }
        }

        public enum Type
        {
            FILE_INFO = 0, 
            DATA = 1,
            HEARTBEAT = 2,
            ACK = 3,
            NACK = 4,
            DISCONNECT = 5,
            STOP = 6,
        }

        public Type GetType()
        {
            return type;
        }
    }
}
