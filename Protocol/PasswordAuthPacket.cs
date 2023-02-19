using SecureSend.Utils;
using System;
using System.Linq;

namespace SecureSend.Protocol
{
    internal class PasswordAuthResponsePacket : Packet
    {
        byte[] passwordHash;
        string salt;
        string username;

        public PasswordAuthResponsePacket(string username, byte[] passwordHash, string salt) : base(PacketType.PASSWORD_AUTH_RESP)
        {
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.username = username;
        }

        protected override byte[] EncodePayload()
        {
            return EncodeVarLengthString(this.username)
                .Concat(EncodeVarLengthBytes(this.passwordHash))
                .Concat(EncodeVarLengthString(this.salt)).ToArray();
        }

        public static PasswordAuthResponsePacket DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            PacketDecoder decoder = new PacketDecoder();
            string username = decoder.DecodeVarLengthString(payloadBytes);
            byte[] hash = decoder.DecodeVarLengthBytes(payloadBytes);
            string salt = decoder.DecodeVarLengthString(payloadBytes);

            return new PasswordAuthResponsePacket(username, hash, salt);
        }

        public byte[] PasswordHash { get { return passwordHash; } }
        public string Salt { get { return salt; } }
        public string Username { get { return username; } }

    }
}
