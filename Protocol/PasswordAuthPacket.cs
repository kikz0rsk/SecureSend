using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureSend.Protocol
{
    internal class PasswordAuthPacket : Packet
    {
        byte[] passwordHash;
        string salt;
        string username;

        public PasswordAuthPacket(string username, byte[] passwordHash, string salt) : base(PacketType.PASSWORD_AUTH_RESP)
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

        public static PasswordAuthPacket DecodeFromBytes(ReadOnlySpan<byte> payloadBytes)
        {
            int totalSkip = 0;
            int skip;
            string username = DecodeVarLengthString(payloadBytes, out totalSkip);
            byte[] hash = DecodeVarLengthBytes(payloadBytes.Skip(totalSkip).ToArray(), out skip);
            totalSkip += skip;
            string salt = DecodeVarLengthString(payloadBytes.Skip(totalSkip).ToArray(), out skip);

            return new PasswordAuthPacket(username, hash, salt);
        }

        public byte[] PasswordHash { get { return passwordHash; } }
        public string Salt { get { return salt; } }
        public string Username { get { return username; } }

    }
}
