using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace BP
{
    internal class NetworkUtils
    {
        public byte[] readExactlyBytes(NetworkStream stream, int howManyBytes)
        {
            int read = 0;
            byte[] output = new byte[howManyBytes];

            while(read < howManyBytes)
            {
                read += stream.Read(output, read, howManyBytes - read);
            }

            return output;
        }
    }
}
