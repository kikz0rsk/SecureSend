using NSec.Cryptography;
using SecureSend.Base;
using SecureSend.GUI;
using SecureSend.Protocol;
using SecureSend.Utils;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace SecureSend.Endpoint
{
    public abstract class NetworkEndpoint
    {
        protected Key? symmetricKey;
        protected PublicKey remoteEndpointPublicKey;
        protected byte[] deviceFingerprint;
        protected string? remoteComputerName;
        protected byte[]? sessionId;
        protected SharedSecret? sharedSecret;

        protected NetworkStream? stream;
        protected TcpClient? connection;

        protected ConcurrentQueue<string> filesToSend = new ConcurrentQueue<string>();

        protected SecureSendApp application;

        protected volatile bool connected = false;
        protected volatile bool client = false;
        protected byte[] lastSequenceForNonce = new byte[6];

        protected CipherAlgorithm cipherAlgorithm = CipherAlgorithm.AES256;

        public NetworkEndpoint(SecureSendApp application)
        {
            this.application = application;
        }

        protected void SendUnencryptedSegment(Segment segment)
        {
            byte[] serializedSegment = segment.BuildSegment();

            byte[] bytesToSend = Segment.EncodeUShort(Convert.ToUInt16(serializedSegment.Length)).Concat(serializedSegment).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Segment? ReceiveUnencryptedSegment()
        {
            ushort segmentLength = Segment.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));
            byte[] segmentBytes = NetworkUtils.ReadExactlyBytes(stream, segmentLength);

            Segment? segment = Segment.Deserialize(segmentBytes);

            return segment;
        }

        protected void SendEncryptedSegment(Segment segment)
        {
            byte[] serializedSegment = segment.BuildSegment();

            byte[] nonceRandom = new byte[6];
            CryptoUtils.FillWithRandomBytes(nonceRandom);

            byte[] nonce = nonceRandom.Concat(lastSequenceForNonce).ToArray();
            IncrementNonce();

            byte[] encryptedPayload = AeadAlgorithm.Aes256Gcm.Encrypt(symmetricKey, nonce, null, serializedSegment);

            byte[] segmentLengthBytes = Segment.EncodeUShort(Convert.ToUInt16(encryptedPayload.Length + 12)); // Nonce is 12 bytes
            byte[] bytesToSend = segmentLengthBytes.Concat(nonce).Concat(encryptedPayload).ToArray();
            stream.Write(bytesToSend, 0, bytesToSend.Length);
        }

        protected Segment ReceiveSegment()
        {
            while(true)
            {
                ushort segmentLength = Segment.DecodeUShort(NetworkUtils.ReadExactlyBytes(stream, 2));

                byte[] encryptedSegment = NetworkUtils.ReadExactlyBytes(stream, segmentLength);

                byte[] nonce = encryptedSegment.Take(12).ToArray();
                byte[] payload = encryptedSegment.Skip(12).ToArray();
                byte[]? decryptedSegmentBytes = CryptoUtils.DecryptBytes(payload, symmetricKey, nonce);

                if (decryptedSegmentBytes == null) continue;

                Segment? segment = Segment.Deserialize(decryptedSegmentBytes);

                if (segment == null) continue;

                return segment;
            }
        }

        protected abstract Key? EstablishTrust();

        protected void _ChangeCipher(CipherAlgorithm algo, byte[] salt)
        {
            cipherAlgorithm = algo;
            Key? key = null;
            switch (algo)
            {
                case CipherAlgorithm.ChaCha20Poly1305:
                    key = KeyDerivationAlgorithm.HkdfSha512.DeriveKey(
                        sharedSecret, salt, null, AeadAlgorithm.ChaCha20Poly1305, CryptoUtils.AllowExport());
                    break;
                case CipherAlgorithm.XChaCha20Poly1305:
                    key = KeyDerivationAlgorithm.HkdfSha512.DeriveKey(
                        sharedSecret, salt, null, AeadAlgorithm.XChaCha20Poly1305, CryptoUtils.AllowExport());
                    break;
                default:
                    key = KeyDerivationAlgorithm.HkdfSha512.DeriveKey(
                        sharedSecret, salt, null, AeadAlgorithm.Aes256Gcm, CryptoUtils.AllowExport());
                    break;
            }
            this.sessionId = salt;
            this.symmetricKey = key;
        }

        protected void ReceiveFile()
        {
            Application.Current.Dispatcher.Invoke(new Action(() =>
            {
                application.MainWindow.fileProgressBar.IsIndeterminate = true;
                application.MainWindow.sendFileButton.IsEnabled = false;
                application.MainWindow.statusText.Content = "Odosielacie zariadenie začína prenos";
            }));

            Segment segment = ReceiveSegment();

            FileInfoSegment fileInfo = (FileInfoSegment)segment;

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
                    Segment dataSegment = ReceiveSegment();

                    if (dataSegment.Type != SegmentType.DATA)
                    {
                        continue;
                    }

                    byte[] data = ((DataSegment)dataSegment).GetData();

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
                    SendEncryptedSegment(new AckSegment());
                    Task.Run(() =>
                    {
                        MessageBox.Show("Súbor " + fileInfo.GetFileName() + " bol úspešne prijatý", "Súbor prijatý", MessageBoxButton.OK, MessageBoxImage.Information);
                    });
                }
                else
                {
                    SendEncryptedSegment(new NackSegment());
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

            SendEncryptedSegment(new PrepareTransferSegment());

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

            FileInfoSegment fileInfoSegment = new FileInfoSegment(Path.GetFileName(filePathString), totalBytes, hash);
            SendEncryptedSegment(fileInfoSegment);

            ulong bytesSent = 0;
            using (Stream fileStream = File.OpenRead(filePathString))
            {
                byte[] buffer = new byte[40_000];
                int bytesRead;
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    DataSegment data = new DataSegment(buffer.Take(bytesRead).ToArray());
                    SendEncryptedSegment(data);
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

            Segment result = ReceiveSegment();

            if (result.Type == SegmentType.ACK)
            {
                Task.Run(() =>
                {
                    MessageBox.Show("Súbor " + fileInfoSegment.GetFileName() + " bol úspešne odoslaný",
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

        protected bool AuthorizeAccess(bool client = false)
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
                    client, remoteComputerName, endpoint.Address.ToString(), deviceFingerprint, rawPublicKey);
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
                    rawPublicKey, remoteComputerName ?? "");
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

                        Segment segment = ReceiveSegment();

                        switch(segment.Type)
                        {
                            case SegmentType.PREPARE_TRANSFER:
                                ReceiveFile();
                                break;
                            case SegmentType.CIPHER_CHANGE:
                                var cipherChange = (CipherChangeSegment)segment;
                                _ChangeCipher(cipherChange.Algorithm, cipherChange.Salt);
                                break;
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
                catch (SocketException ex)
                {
                    Debug.WriteLine(ex.ToString());
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
