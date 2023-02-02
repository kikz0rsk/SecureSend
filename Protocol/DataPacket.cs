﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal class DataPacket : Packet
    {
        protected byte[] data;

        public DataPacket(byte[] data) : base(PacketType.DATA)
        {
            this.data = data;
        }

        protected override byte[] EncodePayload()
        {
            return data;
        }

        public byte[] GetData()
        {
            return data;
        }

    }
}
