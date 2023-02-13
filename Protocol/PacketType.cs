namespace SecureSend.Protocol
{
    public enum PacketType
    {
        SERVER_HANDSHAKE = 0,
        CLIENT_HANDSHAKE = 1,
        FILE_INFO = 2,
        DATA = 3,
        HEARTBEAT = 4,
        ACK = 5,
        NACK = 6,
        DISCONNECT = 7,
        STOP = 8,
        PASSWORD_AUTH_REQ = 9,
        PASSWORD_AUTH_RESP = 10,
    }
}
