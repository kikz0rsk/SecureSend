using SecureSend.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Utils
{
    internal class NetworkUtils
    {
        public static byte[] ReadExactlyBytes(NetworkStream stream, uint howManyBytes)
        {
            int totalRead = 0;
            byte[] output = new byte[howManyBytes];

            while (totalRead < howManyBytes)
            {
                int read = stream.Read(output, totalRead, (int)howManyBytes - totalRead);

                if (read == 0)
                {
                    throw new ConnectionClosedException();
                }

                totalRead += read;
            }

            return output;
        }

        // Convert between Big-endian and Low-endian
        public static void EnsureCorrectEndianness(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
        }
    }
}
