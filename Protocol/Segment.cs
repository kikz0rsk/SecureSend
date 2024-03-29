﻿using SecureSend.Utils;
using System;
using System.Linq;
using System.Text;

namespace SecureSend.Protocol
{
    public abstract class Segment
    {
        public Segment(SegmentType type)
        {
            Type = type;
        }

        public byte[] BuildSegment()
        {
            byte[] payload = EncodePayload();
            byte[] header = { (byte)Type };
            return header.Concat(payload).ToArray();
        }

        protected abstract byte[] EncodePayload();

        public static Segment? Deserialize(ReadOnlySpan<byte> segmentBytes)
        {
            SegmentType? typeCode = (SegmentType)segmentBytes[0];

            var payload = segmentBytes.Slice(1);
            switch (typeCode)
            {
                case SegmentType.DATA:
                    return new DataSegment(payload);
                case SegmentType.FILE_INFO:
                    return FileInfoSegment.DecodeFromBytes(payload);
                case SegmentType.PREPARE_TRANSFER:
                    return new PrepareTransferSegment();
                case SegmentType.ACK:
                    return new AckSegment();
                case SegmentType.NACK:
                    return new NackSegment();
                case SegmentType.SERVER_HANDSHAKE:
                    return ServerHandshake.DecodeFromBytes(payload);
                case SegmentType.CLIENT_HANDSHAKE:
                    return ClientHandshake.DecodeFromBytes(payload);
                case SegmentType.PASSWORD_AUTH_REQ:
                    return PasswordAuthRequestSegment.DecodeFromBytes(payload);
                case SegmentType.PASSWORD_AUTH_RESP:
                    return PasswordAuthResponseSegment.DecodeFromBytes(payload);
                case SegmentType.CIPHER_CHANGE:
                    return CipherChangeSegment.DecodeFromBytes(payload);
                default:
                    return null;
            }
        }

        public static byte[] EncodeInteger(int number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static int DecodeInteger(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 4).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }

        public static byte[] EncodeUShort(ushort number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ushort DecodeUShort(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 2).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt16(bytes, 0);
        }

        public static byte[] EncodeULong(ulong number)
        {
            byte[] numberBytes = BitConverter.GetBytes(number);
            NetworkUtils.EnsureCorrectEndianness(numberBytes);
            return numberBytes;
        }

        public static ulong DecodeULong(ReadOnlySpan<byte> input)
        {
            byte[] bytes = input.Slice(0, 8).ToArray();
            NetworkUtils.EnsureCorrectEndianness(bytes);
            return BitConverter.ToUInt64(bytes, 0);
        }

        public static byte[] EncodeVarLengthBytes(byte[] bytes)
        {
            byte[] encodedLength = EncodeUShort(Convert.ToUInt16(bytes.Length));
            return encodedLength.Concat(bytes).ToArray();
        }

        public static byte[] DecodeVarLengthBytes(ReadOnlySpan<byte> input, out int totalLength)
        {
            int length = DecodeUShort(input);
            totalLength = 2 + length;
            return input.Slice(2, length).ToArray();
        }

        public static byte[] EncodeVarLengthString(string str)
        {
            byte[] encodedString = UTF8Encoding.UTF8.GetBytes(str);
            byte[] encodedLength = EncodeUShort(Convert.ToUInt16(encodedString.Length));
            return encodedLength.Concat(encodedString).ToArray();
        }

        public static string DecodeVarLengthString(ReadOnlySpan<byte> input, out int totalLength)
        {
            int length = DecodeUShort(input);
            totalLength = 2 + length;
            return UTF8Encoding.UTF8.GetString(input.Slice(2, length));
        }

        public SegmentType Type { get; }
    }
}
