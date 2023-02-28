using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    public enum CipherAlgorithm
    {
        AES256 = 0,
        ChaCha20Poly1305 = 1
    }
}
