using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using BP.Protocol;
using NSec.Cryptography;

namespace BP.Networking
{
    internal class NetworkEndpoint
    {
        protected Key? symmetricKey;
        protected NetworkStream stream;
        protected TcpClient? connection;
        protected ConcurrentQueue<string> filesToSend = new ConcurrentQueue<string>();
        protected MainWindow mainWindow;
        protected volatile bool connected = false;

        protected void SendPacket(Packet packet)
        {
            byte[] nonce;
            byte[] serializedPacket = packet.Serialize();
            byte[] encryptedPayload = CryptoUtils.EncryptBytes(serializedPacket, symmetricKey, out nonce);
            byte[] packetLengthBytes = BitConverter.GetBytes(Convert.ToUInt16(encryptedPayload.Length + 12)); // Nonce is 12 bytes
            NetworkUtils.EnsureCorrectEndianness(packetLengthBytes);
            byte[] bytesToSend = packetLengthBytes.Concat(nonce).Concat(encryptedPayload).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Packet? ReceivePacket()
        {
            byte[] packetLengthRaw = NetworkUtils.ReadExactlyBytes(stream, 2);
            NetworkUtils.EnsureCorrectEndianness(packetLengthRaw);
            uint packetLength = BitConverter.ToUInt16(packetLengthRaw, 0);

            byte[] encryptedPacket = NetworkUtils.ReadExactlyBytes(stream, packetLength);

            byte[] nonce = encryptedPacket.Take(12).ToArray();
            byte[] payload = encryptedPacket.Skip(12).ToArray();
            byte[]? decryptedPacketBytes = CryptoUtils.DecryptBytes(payload, symmetricKey, nonce);

            if (decryptedPacketBytes == null) throw new InvalidDataException("Could not decrypt packet");

            Packet? packet = Packet.Deserialize(decryptedPacketBytes);

            if (packet == null) throw new InvalidDataException("Could not deserialize packet");

            return packet;
        }

        protected Key? EstablishTrust()
        {
            // send public key
            stream.Write(mainWindow.ClientKeyPair.PublicKey.Export(KeyBlobFormat.RawPublicKey), 0, 32);

            // get other endpoint's public key
            byte[] otherEndpointPublicKey = NetworkUtils.ReadExactlyBytes(stream, 32);

            PublicKey serverPublicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, otherEndpointPublicKey, KeyBlobFormat.RawPublicKey);

            // agree on shared secret
            SharedSecret sharedSecret = KeyAgreementAlgorithm.X25519.Agree(mainWindow.ClientKeyPair, serverPublicKey);

            if (sharedSecret == null)
            {
                return null;
            }

            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(sharedSecret, null, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
        }

        protected void ReceiveFile(FileInfoPacket fileInfo)
        {
            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.statusText.Content = "Incoming file: " + fileInfo.GetFileName();
                mainWindow.fileProgressBar.Value = 0;
            }));

            ulong totalBytes = fileInfo.GetFileSize();
            using (FileStream fileStream = new FileStream(fileInfo.GetFileName(), FileMode.Create))
            {
                ulong bytesWritten = 0;
                while (bytesWritten < totalBytes)
                {
                    Packet? dataPacket = ReceivePacket();

                    if (dataPacket == null || dataPacket.GetType() != Packet.Type.DATA)
                    {
                        throw new InvalidDataException("GetFile() received invalid packet");
                    }

                    byte[] data = ((DataPacket)dataPacket).GetData();

                    fileStream.Write(data);
                    bytesWritten += (ulong)data.Length;
                    Application.Current.Dispatcher.Invoke(new Action(() => {
                        mainWindow.fileProgressBar.Value = ((float)bytesWritten / totalBytes * 100);
                    }));
                }
            }

            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.fileProgressBar.Value = 100;
                mainWindow.statusText.Content = "Pripravené";
            }));
        }

        protected void SendFile()
        {
            string filepath;
            if (!filesToSend.TryDequeue(out filepath))
            {
                return;
            }

            if (!File.Exists(filepath)) return;

            Application.Current.Dispatcher.Invoke(new Action(() => {
                mainWindow.fileProgressBar.Value = 0;
            }));

            ulong totalBytes = (ulong)new FileInfo(filepath).Length;
            FileInfoPacket fileInfoPacket = new FileInfoPacket(Path.GetFileName(filepath), totalBytes);
            SendPacket(fileInfoPacket);

            ulong bytesSent = 0;
            using (Stream fileStream = File.OpenRead(filepath))
            {
                byte[] buffer = new byte[40_000];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    DataPacket data = new DataPacket(buffer.Take(bytesRead).ToArray());
                    SendPacket(data);
                    bytesSent += (ulong)bytesRead;
                    Application.Current.Dispatcher.Invoke(new Action(() => {
                        mainWindow.fileProgressBar.Value = ((float)bytesSent / totalBytes * 100);
                    }));
                }
            }
        }

        protected void CommunicationLoop()
        {
            while (connection.Connected)
            {
                //connection.Client.Poll(-1, SelectMode.SelectRead);

                try
                {
                    if (stream.DataAvailable)
                    {
                        Packet? packet = ReceivePacket();

                        if (packet == null)
                        {
                            throw new InvalidDataException("Data available in stream but failed to get packet");
                        }

                        if (packet.GetType() != Packet.Type.FILE_INFO)
                        {
                            throw new InvalidDataException("Invalid packet type, expected file info");
                        }

                        ReceiveFile((FileInfoPacket)packet);
                    }
                    else if (filesToSend.Count > 0)
                    {
                        SendFile();
                    } else
                    {
                        Thread.Sleep(100);
                    }
                } catch(SocketException ex)
                {
                    break;
                }
            }
        }

        public void Disconnect()
        {
            stream?.Close();
            connection?.Close();
        }

        public ConcurrentQueue<string> GetFilesToSend()
        {
            return filesToSend;
        }

        public void SetConnected(bool connected)
        {
            this.connected = connected;
            if(connected)
            {
                Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.SetConnected(); }));
                return;
            }

            Application.Current.Dispatcher.Invoke(new Action(() => { mainWindow.SetDisconnected(); }));
        }

        public bool IsConnected()
        {
            return connected;
        }
    }
}
