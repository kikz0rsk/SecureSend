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
            return BitConverter.GetBytes((byte)type).Concat(payload).ToArray();
        }

        protected abstract byte[] SerializePayload();

        public static Packet? Deserialize(byte[] packetBytes) {
            Type? opCode = (Type)packetBytes[0];

            /*if (opCode == null)
            {
                return null;
            }*/

            switch (opCode)
            {
                case Type.FILE_INFO:
                    byte[] fileSizeRaw = packetBytes.Skip(1).Take(8).ToArray();
                    NetworkUtils.EnsureCorrectEndianness(fileSizeRaw);
                    ulong fileSize = BitConverter.ToUInt64(fileSizeRaw, 0);

                    string filename = UTF8Encoding.UTF8.GetString( packetBytes.Skip(9).ToArray() );
                    return new FileInfoPacket(filename, fileSize);
                case Type.DATA:
                    return new DataPacket(packetBytes.Skip(1).ToArray());
                default:
                    return null;
            }
        }

        public enum Type
        {
            FILE_INFO, DATA
        }

        public Type GetType()
        {
            return type;
        }
    }
}
