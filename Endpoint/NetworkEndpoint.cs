using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SecureSend.Protocol;
using NSec.Cryptography;
using SecureSend.Utils;
using SecureSend.Base;
using SecureSend.GUI;
using System.Net;
using System.Reflection;

namespace SecureSend.Endpoint
{
    public abstract class NetworkEndpoint
    {
        protected Key? symmetricKey;
        protected PublicKey remoteEndpointPublicKey;
        protected byte[] deviceFingerprint;

        protected NetworkStream? stream;
        protected TcpClient? connection;

        protected ConcurrentQueue<string> filesToSend = new ConcurrentQueue<string>();

        protected SecureSendApp application;

        protected volatile bool connected = false;
        protected volatile bool client = false;
        protected byte[] lastSequenceForNonce = new byte[6];

        public NetworkEndpoint(SecureSendApp application)
        {
            this.application = application;
        }

        protected void SendUnencryptedPacket(Packet packet)
        {
            byte[] serializedPacket = packet.BuildPacket();

            byte[] bytesToSend = Packet.EncodeUShort(Convert.ToUInt16(serializedPacket.Length)).Concat(serializedPacket).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Packet? ReceiveUnencryptedPacket()
        {
            ushort packetLength = Packet.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));
            byte[] packetBytes = NetworkUtils.ReadExactlyBytes(stream, packetLength);

            Packet? packet = Packet.Deserialize(packetBytes);

            return packet;
        }

        protected void SendPacket(Packet packet)
        {
            byte[] serializedPacket = packet.BuildPacket();

            byte[] nonceRandom = new byte[6];
            CryptoUtils.FillWithRandomBytes(nonceRandom);

            byte[] nonce = nonceRandom.Concat(lastSequenceForNonce).ToArray();
            IncrementNonce();

            byte[] encryptedPayload = AeadAlgorithm.Aes256Gcm.Encrypt(symmetricKey, nonce, null, serializedPacket);

            byte[] packetLengthBytes = Packet.EncodeUShort(Convert.ToUInt16(encryptedPayload.Length + 12)); // Nonce is 12 bytes
            byte[] bytesToSend = packetLengthBytes.Concat(nonce).Concat(encryptedPayload).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Packet ReceivePacket()
        {
            while(true)
            {
                ushort packetLength = Packet.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));

                byte[] encryptedPacket = NetworkUtils.ReadExactlyBytes(stream, packetLength);

                byte[] nonce = encryptedPacket.Take(12).ToArray();
                byte[] payload = encryptedPacket.Skip(12).ToArray();
                byte[]? decryptedPacketBytes = CryptoUtils.DecryptBytes(payload, symmetricKey, nonce);

                if (decryptedPacketBytes == null) continue;

                Packet? packet = Packet.Deserialize(decryptedPacketBytes);

                if (packet == null) continue;

                return packet;
            }
        }

        protected abstract Key? EstablishTrust();

        protected void ReceiveFile()
        {
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.statusText.Content = "Odosielacie zariadenie začína prenos";
            }));

            Packet packet = ReceivePacket();

            FileInfoPacket fileInfo = (FileInfoPacket)packet;

            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.statusText.Content = "Prichádzajúci súbor " + fileInfo.GetFileName();
                application.MainWindow.fileProgressBar.Value = 0;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
            }));

            ulong totalBytes = fileInfo.GetFileSize();

            string saveFolder = Application.Current.Dispatcher.Invoke(() =>
            {
                return application.MainWindow.saveFolderLocation.Text.Trim();
            });

            string savePath = Path.Combine(saveFolder, fileInfo.GetFileName());

            using (FileStream fileStream = new FileStream(savePath, FileMode.Create))
            {
                ulong bytesWritten = 0;
                while (bytesWritten < totalBytes)
                {
                    Packet dataPacket = ReceivePacket();

                    if (dataPacket.GetPacketType() != PacketType.DATA)
                    {
                        throw new InvalidDataException("GetFile() received invalid packet");
                    }

                    byte[] data = ((DataPacket)dataPacket).GetData();

                    fileStream.Write(data);
                    bytesWritten += (ulong)data.Length;
                    Application.Current.Dispatcher.InvokeAsync(new Action(() =>
                    {
                        application.MainWindow.SetProgress(bytesWritten, totalBytes);
                    }));
                }
            }

            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.statusText.Content = "Overuje sa kontrolný súčet súboru...";
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
            }));

            try
            {
                byte[] hash = CryptoUtils.CalculateFileHash(savePath);

                bool isValid = Enumerable.SequenceEqual(fileInfo.GetHash(), hash);
                if (isValid)
                {
                    SendPacket(new AckPacket());
                    Task.Run(() =>
                    {
                        MessageBox.Show("Súbor " + fileInfo.GetFileName() + " bol úspešne prijatý", "Súbor prijatý", MessageBoxButton.OK, MessageBoxImage.Information);
                    });
                }
                else
                {
                    SendPacket(new NackPacket());
                    Task.Run(() =>
                    {
                        MessageBox.Show("Kontrolný súčet sa nezhoduje! Súbor je pravdepodobne poškodený. Zopakujte prenos.", "Súbor je poškodený",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    });
                }
            }
            catch (Exception ex)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Integritu súboru sa nepodarilo overiť: " + ex.ToString(), "Chyba pri overovaní súboru",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }

            Application.Current.Dispatcher.InvokeAsync(new Action(() =>
            {
                application.MainWindow.SetProgress(0, 1);
                application.MainWindow.statusText.Content = "Súbor bol prijatý";
                application.MainWindow.sendFileButton.IsEnabled = true;
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
            }));
        }

        protected void SendFile()
        {
            string? filePathString;
            if (!filesToSend.TryDequeue(out filePathString))
            {
                return;
            }

            if (filePathString == null || !File.Exists(filePathString)) return;

            SendPacket(new PrepareTransferPacket());

            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.fileProgressBar.Value = 0;
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.statusText.Content = "Počíta sa kontrolný súčet súboru...";
            }));

            ulong totalBytes = (ulong)new FileInfo(filePathString).Length;

            byte[] hash = CryptoUtils.CalculateFileHash(filePathString);

            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
                application.MainWindow.statusText.Content = "Odosiela sa súbor...";
            }));

            FileInfoPacket fileInfoPacket = new FileInfoPacket(Path.GetFileName(filePathString), totalBytes, hash);
            SendPacket(fileInfoPacket);

            ulong bytesSent = 0;
            using (Stream fileStream = File.OpenRead(filePathString))
            {
                byte[] buffer = new byte[40_000];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    DataPacket data = new DataPacket(buffer.Take(bytesRead).ToArray());
                    SendPacket(data);
                    bytesSent += (ulong)bytesRead;
                    Application.Current.Dispatcher.InvokeAsync(new Action(() =>
                    {
                        application.MainWindow.SetProgress(bytesSent, totalBytes);
                    }));
                }
            }

            Application.Current.Dispatcher.InvokeAsync(new Action(() =>
            {
                application.MainWindow.statusText.Content = "Prijímajúce zariadenie overuje integritu súboru...";
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
            }));

            Packet? result = ReceivePacket();

            if (result.GetPacketType() == PacketType.ACK)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Súbor " + fileInfoPacket.GetFileName() + " bol úspešne odoslaný",
                        "Súbor odoslaný", MessageBoxButton.OK, MessageBoxImage.Information);
                });
            }
            else
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Kontrolný súčet sa nezhoduje! Súbor na druhej strane je pravdepodobne poškodený. Zopakujte prenos.",
                        "Súbor poškodený", MessageBoxButton.OK, MessageBoxImage.Warning);
                });
            }

            Application.Current.Dispatcher.InvokeAsync(new Action(() =>
            {
                application.MainWindow.statusText.Content = "Súbor bol odoslaný";
                application.MainWindow.sendFileButton.IsEnabled = true;
                application.MainWindow.SetProgress(0, 1);
                application.MainWindow.fileProgressBar.IsIndeterminate = false;
            }));
        }

        protected bool AuthorizeAccess()
        {
            byte[] rawPublicKey = remoteEndpointPublicKey.Export(KeyBlobFormat.RawPublicKey);
            if (TrustedEndpointsManager.Instance.Lookup(deviceFingerprint, rawPublicKey))
            {
                return true;
            }

            IPEndPoint endpoint = connection.Client.RemoteEndPoint as IPEndPoint;
            AcceptConnectionResult result = Application.Current.Dispatcher.Invoke(() =>
            {
                AcceptConnection acceptConnection = new AcceptConnection(
                    false, endpoint.Address.ToString(), deviceFingerprint, rawPublicKey);
                acceptConnection.Owner = application.MainWindow;
                acceptConnection.ShowDialog();
                return acceptConnection.Result;
            });

            if (result == AcceptConnectionResult.Reject)
            {
                return false;
            }

            if (result == AcceptConnectionResult.AcceptAndRemember)
            {
                TrustedEndpointsManager.Instance.Add(deviceFingerprint,
                    rawPublicKey);
            }

            return true;
        }

        protected void CommunicationLoop()
        {
            while (connection.Connected)
            {
                try
                {
                    if (connection.Client.Poll(1000, SelectMode.SelectRead))
                    {
                        if (!stream.DataAvailable)
                        {
                            return;
                        }

                        Packet packet = ReceivePacket();

                        if (packet.GetPacketType() == PacketType.PREPARE_TRANSFER)
                        {
                            ReceiveFile();
                        }
                    }
                    else if (filesToSend.Count > 0)
                    {
                        SendFile();
                    }
                    else
                    {
                        Thread.Sleep(100);
                    }
                }
                catch (SocketException)
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
            if (connected)
            {
                Application.Current.Dispatcher.Invoke(new Action(() => { application.MainWindow.SetConnected(); }));
                return;
            }

            Application.Current.Dispatcher.Invoke(new Action(() => { application.MainWindow.SetDisconnected(); }));
        }

        public bool IsConnected()
        {
            return connected;
        }

        protected void IncrementNonce()
        {
            for (int i = 5; i >= 0; i--)
            {
                bool carry = false;
                if (lastSequenceForNonce[i] == 255)
                {
                    lastSequenceForNonce[i] = 0;
                    carry = true;
                    continue;
                }

                lastSequenceForNonce[i]++;
                if (!carry)
                {
                    return;
                }
            }
        }
    }
}
