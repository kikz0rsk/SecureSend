using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BP.Protocol
{
    internal class FileInfoPacket : Packet
    {
        string fileName;
        ulong fileSize;

        public FileInfoPacket(string fileName, ulong fileSize) : base(Type.FILE_INFO)
        {
            this.fileName = fileName;
            this.fileSize = fileSize;
        }

        protected override byte[] SerializePayload()
        {
            byte[] fileLengthBytes = BitConverter.GetBytes(fileSize);
            NetworkUtils.EnsureCorrectEndianness(fileLengthBytes);
            
            return fileLengthBytes.Concat(UTF8Encoding.UTF8.GetBytes(fileName)).ToArray();
        }

        public string GetFileName()
        {
            return fileName;
        }

        public ulong GetFileSize()
        {
            return fileSize;
        }
    }
}
