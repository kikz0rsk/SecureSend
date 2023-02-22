namespace SecureSend.Protocol
{
    public enum SegmentType
    {
        SERVER_HANDSHAKE = 0,
        CLIENT_HANDSHAKE = 1,
        FILE_INFO = 2,
        DATA = 3,
        PREPARE_TRANSFER = 4,
        ACK = 5,
        NACK = 6,
        PASSWORD_AUTH_REQ = 7,
        PASSWORD_AUTH_RESP = 8,
    }
}
